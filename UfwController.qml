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
//
// Adding and removing rules go through the same door. Nothing they carry is
// ever pasted into a command line: run() hands pkexec an argument list, and
// the values in that list have already been checked against a shape by
// Model.js before they get here. The terminal fallback is the one path that
// does have to produce a line of shell, and it quotes every argument itself.
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

  // "" | "toggle" | "reload" | "add" | "delete" — which command is in flight,
  // so a row can show its own spinner rather than the whole panel greying out.
  property string actionKind: ""

  // Raised when a rule command comes back clean. The panel uses it to close
  // the add form only once ufw has actually taken the rule.
  signal ruleCommitted(string kind)

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

  // Where ufw is, found by probing these absolute paths rather than by asking
  // the session PATH. Whatever ends up here is the argument to pkexec, so it
  // has to be a path the user's environment cannot choose: a writable entry
  // early in PATH — a shared directory, a forgotten ~/.local/bin — would
  // otherwise put an arbitrary binary behind ufw's name in the password dialog
  // and run it as root. The list doubles as the allowlist the probe's answer
  // is checked against, so the probe reports which of these exists; it does
  // not get to name a new one.
  readonly property var _ufwCandidates: ["/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw", "/bin/ufw"]
  property string _ufwPath: ""

  // The two setuid helpers, also by absolute path and for a sharper reason
  // than ufw itself. A planted `pkexec` or `sudo` does not get root — it runs
  // as the user like anything else on PATH — but it is handed a user who has
  // just asked for a password prompt and is expecting one, which makes it a
  // very good place to collect the password and pass it on to the real thing.
  readonly property string _pkexecPath: "/usr/bin/pkexec"
  readonly property string _sudoPath: "/usr/bin/sudo"

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
    var command = value ? Model.UFW_COMMANDS.enable : Model.UFW_COMMANDS.disable
    run(command.args, "toggle", command.flags)
  }

  function reloadFirewall() {
    if (!installed || acting || !isOn) return
    root.actionStatus = "Reloading…"
    run(Model.UFW_COMMANDS.reload.args, "reload", Model.UFW_COMMANDS.reload.flags)
  }

  // ---- Rules
  //
  // Both of these take the argument list Model.js built and hand it straight
  // to run(). Neither builds one itself, and neither is given a chance to: a
  // spec that did not validate arrives here as an empty list, which is refused
  // rather than run with whatever survived.

  // A rule the user described in the panel. `spec` is
  // { action, direction, protocol, port, from, comment } — free text in three
  // of those fields, which is why nothing about it is trusted until
  // buildAddArgs has had a look.
  function addRule(spec) {
    if (!installed || acting) return false
    var built = Model.buildAddArgs(spec)
    if (built.error !== "") {
      root.lastError = built.error
      return false
    }
    root.actionStatus = "Adding…"
    run(built.args, "add")
    return true
  }

  // A rule already in the list, named rather than numbered. `ufw delete 3`
  // would mean "whatever is third when the password comes back", which is not
  // necessarily the row that was clicked.
  function deleteRule(row) {
    if (!installed || acting) return false
    if (!row || !row.deleteArgs || row.deleteArgs.length === 0) {
      root.lastError = "That rule cannot be removed from here. Use `sudo ufw status numbered`."
      return false
    }
    root.actionStatus = "Removing…"
    run(row.deleteArgs.slice(), "delete")
    return true
  }

  // Every privileged call goes through here so there is exactly one place that
  // knows how this machine asks for a password.
  function run(args, kind, flags) {
    // No bare-name fallback: an unresolved ufw means not running one at all,
    // rather than handing pkexec a name for it to look up in PATH.
    if (root._ufwPath === "") return
    // Last line of defence, one step from the password dialog: refuse to run
    // at all rather than run a list something has put a stray flag into.
    //
    // Only the payload goes through allArgsSafe. The leading dash that makes
    // `--force` a legitimate flag is the same one that would make a comment
    // field a forgery, so the two halves cannot share a check: flags are held
    // to the allowlist in Model.js instead, and nothing outside this file
    // supplies them.
    if (!Model.allArgsSafe(args) || !Model.allFlagsAllowed(flags)) {
      // Drop the optimistic state with it. A switch left reading "on" against
      // a command that never ran is the one failure this widget must not have.
      root._desired = -1
      root.lastError = "The firewall command was refused before it ran."
      root.actionStatus = ""
      return
    }
    var argv = (flags || []).concat(args)
    var binary = root._ufwPath
    root.lastError = ""
    root.actionKind = String(kind || "")

    if (root.elevation === "terminal") {
      // The one place a command line has to exist. A rule can carry a comment
      // with a space in it, so every argument is quoted on the way out — the
      // list is the truth, and this is only its spelling.
      var line = Util.shellQuote(root._sudoPath) + " " + Util.shellQuote(binary)
      for (var i = 0; i < argv.length; i++) line += " " + Util.shellQuote(argv[i])

      // A terminal owns the password prompt, so nothing here can watch for the
      // exit code. The file watchers are what report the outcome, and the
      // settle timer is what gives up on the optimistic state if the user
      // closes the terminal at the prompt.
      root.terminalRequested(line)
      root.actionStatus = ""
      root.actionKind = ""
      // A rule sent to a terminal has left this widget's hands; the form can
      // close, because the answer is going to arrive as a file change.
      if (kind === "add" || kind === "delete") root.ruleCommitted(String(kind))
      settleTimer.ticks = 0
      settleTimer.restart()
      return
    }

    root.acting = true
    actionProcess.command = [root._pkexecPath, binary].concat(argv)
    actionProcess.running = true
  }

  // A refusal at the password dialog is a decision, not a fault, so it clears
  // the optimistic state without painting an error across the panel.
  function _finishAction(exitCode, message) {
    var kind = root.actionKind
    root.acting = false
    root.actionStatus = ""
    root.actionKind = ""
    if (exitCode === 0) {
      root.lastError = ""
      if (kind === "add" || kind === "delete") root.ruleCommitted(kind)
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
    // /bin/sh by absolute path too: a `sh` taken from PATH would be the same
    // hole one level up, free to print any path it liked for pkexec to run.
    command: ["/bin/sh", "-c", "for p in " + root._ufwCandidates.join(" ") + "; do if [ -x \"$p\" ]; then echo \"$p\"; break; fi; done"]
    stdout: StdioCollector { id: probeStdout; waitForEnd: true }
    onExited: function(exitCode) {
      var found = String(probeStdout.text || "").replace(/^\s+|\s+$/g, "")
      root._ufwPath = root._ufwCandidates.indexOf(found) >= 0 ? found : ""
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
