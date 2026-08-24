import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

// Firewall status in the bar, and the rules behind one click.
//
// The icon is the whole idea: a wall with flames while the firewall is up, the
// same wall with the fire out — and in the theme's urgent colour — while it is
// down. Nothing about "inactive" should be quiet.
//
// The panel underneath reads the firewall off disk and writes to it through
// three controls: the switch on the hero, a form that adds a rule, and a bin
// on each row that takes one away. Everything shown is free; everything that
// changes the system asks for a password, and says which command it is about
// to run before it does.
Panel {
  id: root
  moduleName: "srozen.ufw"
  ipcTarget: "srozen.ufw"
  manageIpc: false

  // "hero" | "rules". The add form and the delete confirmation are modal —
  // while either is up it owns the keyboard outright, and this cursor is
  // parked rather than moved.
  property string focusSection: "hero"
  property int rowIndex: 0
  property bool cursorActive: false
  property string copiedKey: ""

  // ---- The add form.
  //
  // Held here rather than in the form itself so a re-layout cannot quietly
  // reset a half-typed rule, and so the preview line and the Add button can
  // both read the same values.
  property bool formOpen: false
  property string formAction: "allow"
  property string formDirection: "in"
  property string formProtocol: "tcp"
  property string formPort: ""
  property string formFrom: ""
  property string formComment: ""

  // The rule the confirmation dialog is asking about, or null. Removing a rule
  // is the one thing here that cannot be undone with the same click, so it is
  // the one thing that asks twice.
  property var pendingDelete: null
  readonly property bool confirmOpen: pendingDelete !== null
  // How many rows the pending command would actually take out. A rule with no
  // address is one rule to ufw and two rows here, and the dialog should not
  // pretend otherwise.
  readonly property int pendingDeleteSpan: pendingDelete ? Model.matchingDeleteCount(rows, pendingDelete) : 0

  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property var rows: ufw.ruleRows

  // The cursor stops painting while the form or the dialog is up. Both of them
  // own the keyboard, and the shared surfaces are built on the promise that
  // there is exactly one highlight on screen at a time — a mouse wandering over
  // the rule list behind an open form must not break it.
  readonly property bool cursorVisible: cursorActive && !formOpen && !confirmOpen

  // The form's rule, run through the same validation the controller will use
  // before it hands anything to pkexec. Re-evaluates on every keystroke, which
  // is what lets the preview show the command and the button refuse to be
  // pressed until there is one.
  readonly property var formResult: Model.buildAddArgs({
    action: root.formAction,
    direction: root.formDirection,
    protocol: root.formProtocol,
    port: root.formPort,
    from: root.formFrom,
    comment: root.formComment
  })
  readonly property bool formValid: formResult.error === ""
  readonly property string formPreview: formValid ? Model.commandText(formResult.args) : ""

  // The bar icon goes urgent for exactly one reason — the firewall is off and
  // we know it. An unread state is dimmed instead, because a red wall that
  // turned out to mean "still loading" would cost the colour its meaning.
  readonly property bool alarmed: ufw.installed && ufw.stateKnown && !ufw.isOn
  readonly property bool unknown: !ufw.installed || !ufw.stateKnown

  readonly property bool canEditRules: ufw.installed && ufw.rulesReadable

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
  // machine allows — and there is nothing else a click on the body of a row
  // could usefully mean now that removing one has its own button.
  function copyRow(row) {
    if (!row || !row.text) return
    Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(row.text) + " | wl-copy"])
    root.copiedKey = row.key
    copiedTimer.restart()
  }

  // ---- The add form

  function openForm() {
    if (!canEditRules) return
    root.formAction = "allow"
    root.formDirection = "in"
    root.formProtocol = "tcp"
    root.formPort = ""
    root.formFrom = ""
    root.formComment = ""
    root.formOpen = true
    root.cursorActive = false
    Qt.callLater(function() {
      if (portField) portField.forceActiveFocus()
      scrollFormIntoView()
    })
  }

  function closeForm() {
    if (!root.formOpen) return
    root.formOpen = false
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function toggleForm() {
    if (root.formOpen) closeForm()
    else openForm()
  }

  function submitForm() {
    if (!root.formOpen || !root.formValid || ufw.busy) return
    ufw.addRule({
      action: root.formAction,
      direction: root.formDirection,
      protocol: root.formProtocol,
      port: root.formPort,
      from: root.formFrom,
      comment: root.formComment
    })
  }

  // ---- Removing a rule

  function askDelete(row) {
    if (!row || !canEditRules || ufw.busy) return
    if (!row.deleteArgs || row.deleteArgs.length === 0) return
    // Cancel is what Enter lands on. The dialog exists to slow this down, and
    // defaulting to the destructive half would hand back the pause it bought.
    deleteConfirm.selectedIndex = 0
    root.pendingDelete = row
    Qt.callLater(function() { confirmLayer.forceActiveFocus() })
  }

  function cancelDelete() {
    root.pendingDelete = null
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function confirmDelete() {
    var row = root.pendingDelete
    root.pendingDelete = null
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    if (row) ufw.deleteRule(row)
  }

  function deleteCursorRow() {
    ensureCursor()
    if (focusSection !== "rules" || rows.length === 0) return
    askDelete(rows[rowIndex])
  }

  // ---- Scrolling

  function scrollItemIntoView(item) {
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

  function scrollCursorIntoView() {
    if (focusSection !== "rules" || !ruleColumn) return
    if (rowIndex < 0 || rowIndex >= ruleColumn.children.length) return
    scrollItemIntoView(ruleColumn.children[rowIndex])
  }

  function scrollFormIntoView() {
    if (root.formOpen) scrollItemIntoView(addForm)
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // A rule removed under the cursor would otherwise leave it pointing past the
  // end of the list.
  onRowsChanged: ensureCursor()

  onOpenedChanged: if (opened) {
    cursorActive = false
    focusSection = "hero"
    rowIndex = 0
    copiedKey = ""
    formOpen = false
    pendingDelete = null
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
    // The form stays up, with what was typed still in it, until ufw has
    // actually taken the rule — a refused password or a rule ufw rejects
    // leaves the work on screen rather than making the user type it again.
    onRuleCommitted: function(kind) {
      if (kind === "add") root.closeForm()
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
    // Deliberately no add or delete over IPC. Anything on the session bus can
    // reach these handlers, and a rule is a decision that should be made by
    // someone looking at the panel. `ufw` itself is the interface for scripts.
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
      // The form and the dialog are modal. While either is up the panel's own
      // cursor keys would fight the text field for j/k and the dialog for
      // Enter, so the whole state machine steps aside and keys go to whatever
      // holds focus inside.
      blocked: root.formOpen || root.confirmOpen

      onMoveRequested: function(dx, dy) {
        if (!root.cursorActive) { root.cursorActive = true; return }
        root.moveCursor(dx, dy)
      }
      onActivateRequested: if (root.cursorActive) root.activateCursor()
      onCloseRequested: root.close()
      onDeleteRequested: if (root.cursorActive) root.deleteCursorRow()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "t" || t === "T") ufw.toggle()
        else if (t === "r" || t === "R") ufw.refresh()
        else if (t === "a" || t === "A") root.openForm()
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
            hasCursor: root.cursorVisible && root.focusSection === "hero"
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
            visible: root.canEditRules
            width: parent.width
            spacing: Style.space(10)

            Item {
              width: parent.width
              height: Math.max(rulesHeader.implicitHeight, headerActions.implicitHeight)

              PanelSectionHeader {
                id: rulesHeader
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                text: root.rows.length > 0 ? "RULES (" + root.rows.length + ")" : "RULES"
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              Row {
                id: headerActions
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                spacing: Style.space(2)

                // One button for both halves of the form's life: a plus while
                // it is closed, the same button turned into a cross while it
                // is open, so there is never a second place to look.
                PanelActionButton {
                  id: addButton
                  iconText: root.formOpen ? Model.GLYPH_CLOSE : Model.GLYPH_PLUS
                  tooltipText: root.formOpen ? "Discard this rule" : "Add a rule"
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  enabled: !ufw.busy
                  onClicked: root.toggleForm()
                }

                PanelActionButton {
                  id: reloadButton
                  visible: ufw.isOn
                  iconText: Model.GLYPH_REFRESH
                  tooltipText: "Reload the firewall from its rule files"
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  enabled: !ufw.busy
                  onClicked: ufw.reloadFirewall()
                }
              }
            }

            // ---- The form.
            //
            // A bordered surface rather than bare rows: it is the one part of
            // the panel that is not a read-out, and it should look like
            // somewhere you are being asked for something.
            BorderSurface {
              id: addForm
              visible: root.formOpen
              width: parent.width
              implicitHeight: formColumn.implicitHeight + contentTopInset + contentBottomInset
              color: Style.normalFillFor(root.foreground, Color.accent)
              borderSpec: Border.controlSpec("normal", root.foreground, Color.accent)
              radius: Style.cornerRadius
              padding: Style.space(10)

              // Catches Esc from whichever field has focus, so the form always
              // closes on Esc and never lets it through to close the panel.
              Keys.onEscapePressed: function(event) {
                root.closeForm()
                event.accepted = true
              }

              Column {
                id: formColumn
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.leftMargin: addForm.contentLeftInset
                anchors.rightMargin: addForm.contentRightInset
                anchors.topMargin: addForm.contentTopInset
                spacing: Style.space(8)

                ButtonGroup {
                  id: actionChips
                  width: parent.width
                  value: root.formAction
                  options: [
                    { value: "allow", label: "Allow", tooltip: "Let this traffic through" },
                    { value: "deny", label: "Deny", tooltip: "Drop it silently" },
                    { value: "reject", label: "Reject", tooltip: "Refuse it and say so" },
                    { value: "limit", label: "Limit", tooltip: "Allow, but rate-limit repeat connections" }
                  ]
                  foreground: root.foreground
                  background: "transparent"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onChanged: function(value) { root.formAction = value }
                }

                ButtonGroup {
                  id: directionChips
                  width: parent.width
                  value: root.formDirection
                  options: [
                    { value: "in", label: "Incoming", tooltip: "Traffic arriving at this machine" },
                    { value: "out", label: "Outgoing", tooltip: "Traffic leaving this machine" }
                  ]
                  foreground: root.foreground
                  background: "transparent"
                  fontFamily: root.fontFamily
                  fontSize: Style.font.bodySmall
                  onChanged: function(value) { root.formDirection = value }
                }

                RowLayout {
                  width: parent.width
                  spacing: Style.space(8)

                  ColumnLayout {
                    Layout.fillWidth: true
                    spacing: Style.spacing.labelGap

                    FieldLabel { text: "Port" }

                    TextField {
                      id: portField
                      Layout.fillWidth: true
                      placeholderText: "22, 8000:8010, 80,443"
                      text: root.formPort
                      foreground: root.foreground
                      font.family: root.fontFamily
                      onTextChanged: if (text !== root.formPort) root.formPort = text
                      onAccepted: root.submitForm()
                    }
                  }

                  Dropdown {
                    id: protocolDrop
                    label: "Protocol"
                    value: root.formProtocol
                    options: [
                      { value: "tcp", label: "TCP" },
                      { value: "udp", label: "UDP" },
                      { value: "any", label: "Any" }
                    ]
                    foreground: root.foreground
                    fontFamily: root.fontFamily
                    Layout.preferredWidth: Style.space(104)
                    Layout.alignment: Qt.AlignBottom
                    onChanged: function(value) { root.formProtocol = value }
                  }
                }

                FieldLabel { text: "From" }

                TextField {
                  id: fromField
                  width: parent.width
                  placeholderText: "Anywhere, or 192.168.1.0/24"
                  text: root.formFrom
                  foreground: root.foreground
                  font.family: root.fontFamily
                  onTextChanged: if (text !== root.formFrom) root.formFrom = text
                  onAccepted: root.submitForm()
                }

                FieldLabel { text: "Comment" }

                TextField {
                  id: commentField
                  width: parent.width
                  placeholderText: "Why this rule is here"
                  text: root.formComment
                  foreground: root.foreground
                  font.family: root.fontFamily
                  onTextChanged: if (text !== root.formComment) root.formComment = text
                  onAccepted: root.submitForm()
                }

                // The command, spelled out. The rest of this panel is careful
                // to say things the way ufw says them so the two can be
                // checked against each other; a form that hid what it was
                // about to run would be the one place that stopped.
                Text {
                  width: parent.width
                  text: root.formValid ? root.formPreview : root.formResult.error
                  color: root.formValid ? root.dim : root.urgent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                  wrapMode: Text.WordWrap
                }

                Item {
                  width: parent.width
                  height: formButtons.implicitHeight

                  Row {
                    id: formButtons
                    anchors.right: parent.right
                    spacing: Style.space(6)

                    Button {
                      text: "Cancel"
                      bordered: true
                      focusable: true
                      foreground: root.foreground
                      background: "transparent"
                      fontFamily: root.fontFamily
                      fontSize: Style.font.bodySmall
                      onClicked: root.closeForm()
                    }

                    Button {
                      id: commitButton
                      text: "Add rule"
                      iconText: Model.GLYPH_CHECK
                      iconSize: Style.font.bodySmall
                      bordered: true
                      focusable: true
                      selected: root.formValid
                      enabled: root.formValid && !ufw.busy
                      opacity: enabled ? 1.0 : 0.45
                      foreground: root.foreground
                      background: "transparent"
                      fontFamily: root.fontFamily
                      fontSize: Style.font.bodySmall
                      onClicked: root.submitForm()
                    }
                  }
                }
              }
            }

            Text {
              visible: root.rows.length === 0 && !root.formOpen
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

      // ---- Removing a rule, confirmed.
      //
      // Sits above the whole panel rather than inside the row: the question is
      // about the firewall, not about a line in a list, and it should read
      // like the only thing on screen while it is being asked.
      Item {
        id: confirmLayer
        anchors.fill: parent
        visible: root.confirmOpen
        z: 30
        focus: root.confirmOpen

        Keys.onPressed: function(event) {
          if (deleteConfirm.handleKey(event)) event.accepted = true
        }

        ConfirmDialog {
          id: deleteConfirm
          anchors.fill: parent
          opened: root.confirmOpen
          message: root.pendingDelete
            ? "Remove this rule?\n\n" + root.pendingDelete.deleteCommand
              + (root.pendingDeleteSpan > 1 ? "\n\nIts IPv4 and IPv6 rows go together." : "")
            : ""
          cancelText: "Keep"
          confirmText: "Remove"
          background: Color.popups.background
          foreground: root.foreground
          scrim: Util.alpha(Color.popups.background, 0.75)
          fontFamily: root.fontFamily
          onCanceled: root.cancelDelete()
          onConfirmed: root.confirmDelete()
        }
      }
    }
  }

  // A rule reads as what it lets through, with who it applies to underneath —
  // the same two halves `ufw status` prints across its To and From columns.
  // The glyph on the left is the action, so the list can be scanned without
  // reading a word of it; the bin on the right only appears under the cursor,
  // so a list being read cannot be a list being edited by accident.
  component RuleRow: CursorSurface {
    id: ruleRow
    property var row: null
    property int cursorIndex: 0

    readonly property bool denied: row && (row.action === "deny" || row.action === "reject")
    readonly property bool copied: row && root.copiedKey === row.key
    // A rule the model could not write back out as a command is one this
    // widget must not offer to remove — there is no argument list for it, and
    // guessing at one is how the wrong rule gets deleted.
    readonly property bool canDelete: !!(row && row.deleteArgs && row.deleteArgs.length > 0)

    hasCursor: root.cursorVisible && root.focusSection === "rules" && root.rowIndex === cursorIndex
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
      anchors.rightMargin: Style.space(6)
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

      // Reserved whether or not it is showing, so a row does not change width
      // as the cursor passes over it. Urgent on hover, like every other
      // destructive edge action in the shell.
      PanelActionButton {
        id: removeButton
        visible: ruleRow.canDelete
        opacity: ruleRow.hasCursor ? 1.0 : 0.0
        enabled: ruleRow.hasCursor && !ufw.busy
        iconText: Model.GLYPH_TRASH
        tooltipText: "Remove this rule"
        foreground: root.dim
        hoverColor: root.urgent
        fontFamily: root.fontFamily
        fontSize: Style.font.iconSmall
        size: Style.space(22)
        Layout.alignment: Qt.AlignVCenter
        onClicked: root.askDelete(ruleRow.row)

        Behavior on opacity { NumberAnimation { duration: 90 } }
      }
    }
  }

  // The caption above a form field, matching the label Dropdown draws above
  // its own trigger so a labelled field and a labelled dropdown sitting side
  // by side read as one row.
  component FieldLabel: Text {
    color: Qt.darker(root.foreground, 1.4)
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
    font.bold: true
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
