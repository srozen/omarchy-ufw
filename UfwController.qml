import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "Model.js" as Model

// State for the ufw widget: what the firewall is doing, and the two commands
// that change it.
//
// Reading is free. ufw keeps its state in world-readable files under /etc, so
// the bar icon and the rule list cost nothing but a file read — no password,
// no polling a command that would need one. The files are watched, so a rule
// added from a terminal shows up in the panel without the panel being touched.
//
// Writing is not free, and deliberately so. `ufw enable` needs root, which
// means a prompt: pkexec by default, because Omarchy ships a polkit agent and
// the dialog it draws matches the rest of the desktop. A terminal running
// `sudo ufw enable` is the fallback for a session without an agent.
Item {
  id: root

  property var settings: ({})

  // ---- What the firewall is doing.
  //
  // `null` for enabled means "not read yet", which is a different thing from
  // "off" — only one of the two should turn the bar icon red.
  property bool installed: false
  property bool probed: false
  property var fileEnabled: null
  property string logLevel: ""
  property var defaults: ({ input: "deny", output: "allow", forward: "deny", ipv6: true })
  property var ruleRows: []
  property bool rulesReadable: true

  // ---- Transient feedback.
  property bool acting: false
  property string actionStatus: ""
  property string lastError: ""

  // Optimistic state, the same shape the VPN widget's backends use: -1 follows
  // the file, 0/1 override it while a command is in flight. That is what makes
  // the switch throw on the click rather than a file-watch later.
  property int _desired: -1

  // Not called `enabled`: that name belongs to Item, and shadowing it would
  // quietly hand this widget's input handling to the firewall's state.
  readonly property var firewallOn: _desired >= 0 ? _desired === 1 : fileEnabled
  readonly property bool stateKnown: firewallOn !== null && firewallOn !== undefined
  readonly property bool isOn: firewallOn === true
  readonly property bool busy: acting || _desired >= 0

  readonly property string glyph: isOn ? Model.GLYPH_WALL_FIRE : Model.GLYPH_WALL
  readonly property string statusWord: Model.statusWord(installed, firewallOn)
  readonly property string barSummary: Model.barSummary(installed, firewallOn, ruleRows.length)
  readonly property string policySummary: Model.policySummary(defaults)

  // "pkexec" | "terminal". Nothing else is accepted, so a typo in shell.json
  // falls back to the agent rather than to nothing happening.
  readonly property string elevation: {
    var value = String(settings && settings.elevation ? settings.elevation : "pkexec").toLowerCase()
    return value === "terminal" ? "terminal" : "pkexec"
  }

  readonly property int refreshIntervalSec: {
    var value = Number(settings && settings.refreshIntervalSec ? settings.refreshIntervalSec : 30)
    return isFinite(value) && value >= 5 ? Math.round(value) : 30
  }

  // Raised when the elevation setting says a terminal owns the password
  // conversation. The panel forwards it to the bar, which is the only thing
  // here that can launch one.
  signal terminalRequested(string command)

  property string _ufwPath: ""

  function refresh() {
    confFile.reload()
    defaultsFile.reload()
    rulesFile.reload()
    rules6File.reload()
  }

  function toggle() {
    if (!installed) return
    setEnabled(!isOn)
  }

  function setEnabled(value) {
    if (!installed || acting) return
    if (stateKnown && value === isOn) return
    root._desired = value ? 1 : 0
    root.actionStatus = value ? "Enabling…" : "Disabling…"
    run(value ? ["--force", "enable"] : ["disable"])
  }

  function reloadFirewall() {
    if (!installed || acting || !isOn) return
    root.actionStatus = "Reloading…"
    run(["reload"])
  }

  // Every privileged call goes through here so there is exactly one place that
  // knows how this machine asks for a password.
  function run(args) {
    var binary = root._ufwPath !== "" ? root._ufwPath : "ufw"
    root.lastError = ""

    if (root.elevation === "terminal") {
      // A terminal owns the password prompt, so nothing here can watch for the
      // exit code. The file watchers are what report the outcome, and the
      // settle timer is what gives up on the optimistic state if the user
      // closes the terminal at the prompt.
      root.terminalRequested("sudo " + binary + " " + args.join(" "))
      root.actionStatus = ""
      settleTimer.ticks = 0
      settleTimer.restart()
      return
    }

    root.acting = true
    actionProcess.command = ["pkexec", binary].concat(args)
    actionProcess.running = true
  }

  // A refusal at the password dialog is a decision, not a fault, so it clears
  // the optimistic state without painting an error across the panel.
  function _finishAction(exitCode, message) {
    root.acting = false
    root.actionStatus = ""
    if (exitCode === 0) {
      root.lastError = ""
    } else {
      root._desired = -1
      root.lastError = exitCode === 126 || exitCode === 127
        ? ""
        : (String(message || "").replace(/^\s+|\s+$/g, "") || "The firewall command failed.")
    }
    settleTimer.ticks = 0
    settleTimer.restart()
    refresh()
  }

  function _applyConf(text) {
    root.fileEnabled = Model.parseEnabled(text)
    root.logLevel = Model.parseLogLevel(text)
    // Reality has caught up with the click, so stop overriding it.
    if (root._desired >= 0 && root.fileEnabled === (root._desired === 1)) root._desired = -1
  }

  function _applyRules() {
    root.ruleRows = Model.buildRuleRows(rulesFile.text(), rules6File.text())
  }

  Component.onCompleted: probeProcess.running = true

  Process {
    id: probeProcess
    running: false
    command: ["bash", "-c", "command -v ufw || true"]
    stdout: StdioCollector { id: probeStdout; waitForEnd: true }
    onExited: function(exitCode) {
      root._ufwPath = String(probeStdout.text || "").replace(/^\s+|\s+$/g, "")
      root.installed = root._ufwPath !== ""
      root.probed = true
      if (root.installed) root.refresh()
    }
  }

  Process {
    id: actionProcess
    running: false
    command: []
    stdout: StdioCollector { id: actionStdout; waitForEnd: true }
    stderr: StdioCollector { id: actionStderr; waitForEnd: true }
    onExited: function(exitCode) {
      root._finishAction(exitCode, String(actionStderr.text || actionStdout.text || ""))
    }
  }

  // ---- The state files.
  //
  // `text()` is stale inside onFileChanged, so both paths route through
  // reload() → onLoaded and always parse fresh content.

  FileView {
    id: confFile
    path: "/etc/ufw/ufw.conf"
    watchChanges: true
    printErrors: false
    onLoaded: root._applyConf(text())
    onFileChanged: reload()
    onLoadFailed: root.fileEnabled = null
  }

  FileView {
    id: defaultsFile
    path: "/etc/default/ufw"
    watchChanges: true
    printErrors: false
    onLoaded: root.defaults = Model.parseDefaults(text())
    onFileChanged: reload()
  }

  FileView {
    id: rulesFile
    path: "/etc/ufw/user.rules"
    watchChanges: true
    printErrors: false
    onLoaded: {
      root.rulesReadable = true
      root._applyRules()
    }
    onFileChanged: reload()
    // Stock ufw ships these world-readable; a hardened install may not, and
    // the panel says so rather than claiming the firewall has no rules.
    onLoadFailed: {
      root.rulesReadable = false
      root.ruleRows = []
    }
  }

  FileView {
    id: rules6File
    path: "/etc/ufw/user6.rules"
    watchChanges: true
    printErrors: false
    onLoaded: root._applyRules()
    onFileChanged: reload()
  }

  // ---- Timers

  // The watchers do the real work; this is the safety net for a write that
  // lands as a replace rather than a modify and slips past inotify.
  Timer {
    interval: root.refreshIntervalSec * 1000
    running: root.installed
    repeat: true
    onTriggered: root.refresh()
  }

  // ufw rewrites ufw.conf as part of enabling, so the watcher normally beats
  // this. It exists for the case where it does not — a refused password, a
  // closed terminal — so the switch cannot sit flipped against a firewall that
  // never changed.
  Timer {
    id: settleTimer
    property int ticks: 0
    interval: 700
    repeat: true
    running: root._desired >= 0
    onTriggered: {
      ticks += 1
      root.refresh()
      if (ticks >= 12) {
        ticks = 0
        root._desired = -1
        stop()
      }
    }
  }
}
