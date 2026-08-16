import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

// Firewall status in the bar, and everything ufw will tell you without a
// password behind one click.
//
// The icon is the whole idea: a wall with flames while the firewall is up, the
// same wall with the fire out — and in the theme's urgent colour — while it is
// down. Nothing about "inactive" should be quiet.
//
// The panel underneath is a read-out with one control. The switch on the hero
// is the only thing that changes the system, and it is the only thing that
// asks for a password; the default policies, the rule list, and the log level
// are all read straight off disk.
Panel {
  id: root
  moduleName: "srozen.ufw"
  ipcTarget: "srozen.ufw"
  manageIpc: false

  // "hero" | "rules"
  property string focusSection: "hero"
  property int rowIndex: 0
  property bool cursorActive: false
  property string copiedKey: ""

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property var rows: ufw.ruleRows

  // The bar icon goes urgent for exactly one reason — the firewall is off and
  // we know it. An unread state is dimmed instead, because a red wall that
  // turned out to mean "still loading" would cost the colour its meaning.
  readonly property bool alarmed: ufw.installed && ufw.stateKnown && !ufw.isOn
  readonly property bool unknown: !ufw.installed || !ufw.stateKnown

  readonly property string heroMeta: {
    if (!ufw.probed) return "Checking…"
    if (!ufw.installed) return "ufw is not installed"
    if (!ufw.stateKnown) return "Status unavailable"
    if (!ufw.isOn) return "Inactive — nothing is being filtered"
    return "Active  ·  " + rows.length + (rows.length === 1 ? " rule" : " rules")
  }

  readonly property bool statusIsError: ufw.lastError !== ""
  readonly property string statusLine: {
    if (ufw.actionStatus !== "") return ufw.actionStatus
    if (ufw.lastError !== "") return ufw.lastError
    if (ufw.installed && !ufw.rulesReadable)
      return "/etc/ufw/user.rules is not readable by your user, so the rule list is hidden. Run `sudo ufw status numbered` to see it."
    if (!ufw.probed || ufw.installed) return ""
    return "Install ufw with `omarchy pkg add ufw` to use this widget."
  }

  function ensureCursor() {
    if (rows.length === 0 && focusSection === "rules") focusSection = "hero"
    if (rowIndex >= rows.length) rowIndex = Math.max(0, rows.length - 1)
    if (rowIndex < 0) rowIndex = 0
  }

  function moveCursor(dx, dy) {
    cursorActive = true
    ensureCursor()
    if (dy === 0) return

    if (focusSection === "hero") {
      if (dy > 0 && rows.length > 0) setRowCursor(0)
      return
    }
    if (dy < 0 && rowIndex === 0) {
      setHeroCursor()
      return
    }
    rowIndex = Math.max(0, Math.min(rows.length - 1, rowIndex + dy))
    scrollCursorIntoView()
  }

  function setHeroCursor() {
    cursorActive = true
    focusSection = "hero"
    if (panelFlick) panelFlick.contentY = 0
  }

  function setRowCursor(index) {
    cursorActive = true
    focusSection = "rules"
    rowIndex = index
    scrollCursorIntoView()
  }

  function activateCursor() {
    ensureCursor()
    if (focusSection === "hero") ufw.toggle()
    else if (rows.length > 0) copyRow(rows[rowIndex])
  }

  // A rule is worth copying — into a terminal, into a note about what this
  // machine allows — and there is nothing else a click on a read-only row
  // could usefully mean.
  function copyRow(row) {
    if (!row || !row.text) return
    Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(row.text) + " | wl-copy"])
    root.copiedKey = row.key
    copiedTimer.restart()
  }

  function scrollCursorIntoView() {
    if (focusSection !== "rules" || !ruleColumn) return
    if (rowIndex < 0 || rowIndex >= ruleColumn.children.length) return
    var item = ruleColumn.children[rowIndex]
    if (!panelFlick || !item) return
    Qt.callLater(function() {
      if (!item) return
      var margin = Style.space(6)
      var point = item.mapToItem(panelFlick.contentItem, 0, 0)
      var top = point.y
      var bottom = top + item.height
      var viewTop = panelFlick.contentY
      var viewBottom = viewTop + panelFlick.height
      var maxY = Math.max(0, panelFlick.contentHeight - panelFlick.height)
      if (top < viewTop + margin) panelFlick.contentY = Math.max(0, top - margin)
      else if (bottom > viewBottom - margin) panelFlick.contentY = Math.min(maxY, bottom + margin - panelFlick.height)
    })
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    cursorActive = false
    focusSection = "hero"
    rowIndex = 0
    copiedKey = ""
    if (panelFlick) panelFlick.contentY = 0
    ufw.refresh()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  UfwController {
    id: ufw
    settings: root.settings
    // Only reached when the widget is configured to let a terminal own the
    // password prompt; pkexec needs no help from the bar.
    onTerminalRequested: function(command) {
      if (!root.bar) return
      root.bar.run("omarchy-launch-floating-terminal-with-presentation " + Util.shellQuote(command))
      root.close()
    }
  }

  Timer {
    id: copiedTimer
    interval: 1600
    repeat: false
    onTriggered: root.copiedKey = ""
  }

  IpcHandler {
    target: root.ipcTarget

    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { ufw.refresh(); return "ok" }
    function status(): string { return ufw.statusWord }
    function enable(): string {
      if (!ufw.installed) return "ufw not installed"
      ufw.setEnabled(true)
      return "ok"
    }
    function disable(): string {
      if (!ufw.installed) return "ufw not installed"
      ufw.setEnabled(false)
      return "ok"
    }
    function rules(): string {
      return ufw.ruleRows.map(function(row) { return row.text }).join("\n")
    }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ufw.glyph
    // `active` paints the glyph in the bar's urgent colour. Off means red;
    // unknown means faded; on means the ordinary bar foreground.
    active: root.alarmed
    dimmed: root.unknown
    tooltipText: "Firewall: " + ufw.barSummary
    onPressed: function(buttonCode) {
      // Left click opens the panel; middle click re-reads. Nothing on this
      // button turns the firewall off — that is a decision, and it belongs
      // behind the switch in the panel where the state is visible.
      if (buttonCode === Qt.MiddleButton) ufw.refresh()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    // Wider than the VPN panel it borrows its shape from: a rule row carries
    // two addresses and a comment on one line, and the comment is the half
    // that says why the rule is there.
    contentWidth: panel.fittedContentWidth(Style.space(430))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(560))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onMoveRequested: function(dx, dy) {
        if (!root.cursorActive) { root.cursorActive = true; return }
        root.moveCursor(dx, dy)
      }
      onActivateRequested: if (root.cursorActive) root.activateCursor()
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "t" || t === "T") ufw.toggle()
        else if (t === "r" || t === "R") ufw.refresh()
      }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: panelFlick.width
          spacing: Style.space(12)

          // ---- Hero: the state, and the one control that changes it.
          CursorSurface {
            id: heroSurface
            width: parent.width
            implicitHeight: hero.implicitHeight + Style.spacing.rowPaddingX
            hasCursor: root.cursorActive && root.focusSection === "hero"
            foreground: root.foreground

            PanelHero {
              id: hero
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              anchors.leftMargin: Style.space(4)
              anchors.rightMargin: Style.space(4)
              title: "Firewall"
              meta: root.heroMeta
              foreground: root.foreground
              fontFamily: root.fontFamily
              iconOpacity: root.unknown ? 0.5 : 1.0
              iconComponent: Component {
                Text {
                  text: ufw.glyph
                  color: root.alarmed ? root.urgent : (root.unknown ? root.dim : root.foreground)
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.display
                }
              }
              trailingControl: Component {
                ToggleSwitch {
                  id: masterSwitch
                  visible: ufw.installed
                  checked: ufw.isOn
                  busy: ufw.busy
                  foreground: root.foreground
                  // The hero owns the click and the cursor ring, so the switch
                  // must not own them too — one highlight on screen at a time.
                  interactive: false

                  PanelToolTip {
                    visible: masterSwitch.containsMouse
                    text: ufw.isOn ? "Disable the firewall" : "Enable the firewall"
                    fontFamily: root.fontFamily
                  }
                }
              }
            }

            MouseArea {
              anchors.fill: parent
              enabled: ufw.installed
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onEntered: root.setHeroCursor()
              onClicked: ufw.toggle()

              PanelToolTip {
                visible: parent.containsMouse
                text: ufw.isOn ? "Disable the firewall" : "Enable the firewall"
                fontFamily: root.fontFamily
              }
            }
          }

          Text {
            visible: root.statusLine !== ""
            width: parent.width
            text: root.statusLine
            color: root.statusIsError ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // ---- Default policies. What happens to everything the rules below
          //      do not mention, which is most traffic.
          Column {
            visible: ufw.installed
            width: parent.width
            spacing: Style.spacing.labelGap

            InfoPair { label: "Incoming"; value: ufw.defaults.input }
            InfoPair { label: "Outgoing"; value: ufw.defaults.output }
            InfoPair { label: "Routed"; value: ufw.defaults.forward }
            InfoPair { label: "IPv6"; value: ufw.defaults.ipv6 ? "on" : "off" }
            InfoPair {
              label: "Logging"
              value: ufw.logLevel !== "" ? ufw.logLevel : "—"
            }
          }

          PanelSeparator {
            visible: ufw.installed
            foreground: root.foreground
          }

          // ---- The rules themselves, in the order and the wording
          //      `ufw status` uses.
          Column {
            visible: ufw.installed && ufw.rulesReadable
            width: parent.width
            spacing: Style.space(10)

            Item {
              width: parent.width
              height: Math.max(rulesHeader.implicitHeight, reloadButton.implicitHeight)

              PanelSectionHeader {
                id: rulesHeader
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                text: root.rows.length > 0 ? "RULES (" + root.rows.length + ")" : "RULES"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              PanelActionButton {
                id: reloadButton
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                visible: ufw.isOn
                iconText: Model.GLYPH_REFRESH
                tooltipText: "Reload the firewall from its rule files"
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: ufw.reloadFirewall()
              }
            }

            Text {
              visible: root.rows.length === 0
              width: parent.width
              text: "No rules. Traffic follows the default policies above."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              horizontalAlignment: Text.AlignHCenter
              wrapMode: Text.WordWrap
            }

            Column {
              id: ruleColumn
              width: parent.width
              spacing: Style.space(6)

              Repeater {
                model: root.rows

                RuleRow {
                  required property var modelData
                  required property int index
                  width: ruleColumn.width
                  row: modelData
                  cursorIndex: index
                }
              }
            }
          }
        }
      }
    }
  }

  // A rule reads as what it lets through, with who it applies to underneath —
  // the same two halves `ufw status` prints across its To and From columns.
  // The glyph on the left is the action, so the list can be scanned without
  // reading a word of it.
  component RuleRow: CursorSurface {
    id: ruleRow
    property var row: null
    property int cursorIndex: 0

    readonly property bool denied: row && (row.action === "deny" || row.action === "reject")
    readonly property bool copied: row && root.copiedKey === row.key

    hasCursor: root.cursorActive && root.focusSection === "rules" && root.rowIndex === cursorIndex
    foreground: root.foreground

    implicitHeight: ruleContent.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      id: ruleMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onEntered: root.setRowCursor(ruleRow.cursorIndex)
      onClicked: root.copyRow(ruleRow.row)

      PanelToolTip {
        visible: ruleMouse.containsMouse
        text: ruleRow.copied ? "Copied" : "Click to copy"
        fontFamily: root.fontFamily
      }
    }

    RowLayout {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      spacing: Style.space(8)

      Text {
        text: ruleRow.row ? ruleRow.row.glyph : ""
        // A deny rule is doing its job, so it is not urgent — but it is the
        // one kind of row worth picking out of a list that is mostly allows.
        color: ruleRow.denied ? root.urgent : root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.icon
        Layout.alignment: Qt.AlignVCenter
      }

      ColumnLayout {
        id: ruleContent
        Layout.fillWidth: true
        spacing: Style.space(1)

        Text {
          Layout.fillWidth: true
          text: ruleRow.row ? ruleRow.row.label : ""
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          elide: Text.ElideRight
        }

        Text {
          Layout.fillWidth: true
          text: ruleRow.row ? ruleRow.row.verb + "  ·  " + ruleRow.row.detail : ""
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      Text {
        visible: ruleRow.row !== null
        text: ruleRow.row ? ruleRow.row.directionGlyph : ""
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.iconSmall
        Layout.alignment: Qt.AlignVCenter
      }
    }
  }

  // Label left, value right, with the gap between them doing the aligning —
  // the same pair the network and bluetooth panels use for their detail rows.
  component InfoPair: Row {
    id: pair
    property string label: ""
    property string value: ""

    width: parent.width
    spacing: Style.space(8)

    Text {
      id: pairLabel
      text: pair.label
      color: root.foreground
      opacity: 0.6
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
    }

    Item {
      width: Math.max(0, pair.width - pairLabel.implicitWidth - pairValue.implicitWidth - pair.spacing * 2)
      height: 1
    }

    Text {
      id: pairValue
      text: pair.value
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      elide: Text.ElideRight
    }
  }
}
