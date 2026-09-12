.pragma library

// Pure parsing for the ufw widget: config files in, display rows out. No QML
// and no side effects, so the whole of it runs under node (tests/run.js).
//
// Everything the widget shows is read straight from ufw's own state files,
// which are world-readable on a stock install:
//
//   /etc/ufw/ufw.conf     ENABLED / LOGLEVEL
//   /etc/default/ufw      the three default policies, and whether v6 is on
//   /etc/ufw/user.rules   the v4 rules, as `### tuple ###` lines
//   /etc/ufw/user6.rules  the v6 rules, same format
//
// That is what makes the bar icon honest without a password: `ufw status`
// needs root only because it shells out to iptables to check the firewall is
// loaded, and the rules it prints come from these same tuples.

// Nerd Font glyphs are built from codepoints instead of raw characters so the
// file survives editing tools that mangle multi-byte sequences.

// The bar icon, and the whole point of the widget: a wall with flames when the
// firewall is up, the same wall with the fire gone out when it is not.
var GLYPH_WALL_FIRE = String.fromCodePoint(0xF1A11)
var GLYPH_WALL = String.fromCodePoint(0xF07FE)

// One per ufw action, so a list of rules can be read down the left edge
// without parsing the words.
var GLYPH_ALLOW = String.fromCodePoint(0xF0565)
var GLYPH_DENY = String.fromCodePoint(0xF0ADC)
var GLYPH_REJECT = String.fromCodePoint(0xF0ECC)
var GLYPH_LIMIT = String.fromCodePoint(0xF04C5)

var GLYPH_INBOUND = String.fromCodePoint(0xF072E)
var GLYPH_OUTBOUND = String.fromCodePoint(0xF0737)
var GLYPH_ROUTED = String.fromCodePoint(0xF04E1)

var GLYPH_SHIELD = String.fromCodePoint(0xF0498)
var GLYPH_REFRESH = String.fromCodePoint(0xF0450)
var GLYPH_CHEVRON_DOWN = String.fromCodePoint(0xF0140)
var GLYPH_CHEVRON_UP = String.fromCodePoint(0xF0143)

// The three verbs of rule management, in the same visual family as the rest:
// a plus to open the form, a check to commit it, a bin to take a rule away.
var GLYPH_PLUS = String.fromCodePoint(0xF0415)
var GLYPH_CHECK = String.fromCodePoint(0xF012C)
var GLYPH_CLOSE = String.fromCodePoint(0xF0156)
var GLYPH_TRASH = String.fromCodePoint(0xF0A7A)

var ANY_V4 = "0.0.0.0/0"
var ANY_V6 = "::/0"

// ---- /etc/ufw/ufw.conf

// `null` rather than `false` when the key is missing: "we have not read it
// yet" and "the firewall is off" are different states, and only one of them
// should paint the bar icon red.
function parseEnabled(text) {
  var match = /^[ \t]*ENABLED[ \t]*=[ \t]*"?([A-Za-z]+)"?/m.exec(String(text === undefined || text === null ? "" : text))
  if (!match) return null
  return match[1].toLowerCase() === "yes"
}

function parseLogLevel(text) {
  var match = /^[ \t]*LOGLEVEL[ \t]*=[ \t]*"?([A-Za-z]+)"?/m.exec(String(text === undefined || text === null ? "" : text))
  return match ? match[1].toLowerCase() : ""
}

// ---- /etc/default/ufw

// iptables targets, said the way `ufw status verbose` says them, because that
// is the vocabulary the rules below are already written in.
function policyWord(value) {
  var text = String(value === undefined || value === null ? "" : value).replace(/"/g, "").trim().toUpperCase()
  if (text === "DROP") return "deny"
  if (text === "ACCEPT") return "allow"
  if (text === "REJECT") return "reject"
  return text.toLowerCase()
}

function readVariable(text, name) {
  var pattern = new RegExp("^[ \\t]*" + name + "[ \\t]*=[ \\t]*\"?([^\"\\n\\r]*)\"?", "m")
  var match = pattern.exec(String(text === undefined || text === null ? "" : text))
  return match ? match[1].trim() : ""
}

function parseDefaults(text) {
  return {
    input: policyWord(readVariable(text, "DEFAULT_INPUT_POLICY")) || "deny",
    output: policyWord(readVariable(text, "DEFAULT_OUTPUT_POLICY")) || "allow",
    forward: policyWord(readVariable(text, "DEFAULT_FORWARD_POLICY")) || "deny",
    ipv6: String(readVariable(text, "IPV6")).toLowerCase() !== "no"
  }
}

// ---- /etc/ufw/user.rules

// ufw hex-encodes rule comments so a comment can hold anything without
// breaking the single-line tuple format it lives on.
function decodeComment(hex) {
  var text = String(hex === undefined || hex === null ? "" : hex).trim()
  if (text === "" || !/^([0-9a-fA-F]{2})+$/.test(text)) return ""
  var out = ""
  for (var i = 0; i < text.length; i += 2) out += String.fromCharCode(parseInt(text.substr(i, 2), 16))
  // Comments are stored UTF-8; decodeURIComponent turns those bytes back into
  // characters. A comment that is not valid UTF-8 is shown byte-for-byte
  // rather than dropped.
  try {
    return decodeURIComponent(out.split("").map(function(ch) {
      return "%" + ("0" + ch.charCodeAt(0).toString(16)).slice(-2)
    }).join(""))
  } catch (error) {
    return out
  }
}

// One `### tuple ###` line, in the exact shape ufw's own reader expects:
//
//   action proto dport dst sport src ifaces [comment=hex]
//   action proto dport dst sport src dapp sapp ifaces [comment=hex]
//
// Six and eight fields are the pre-direction format, which ufw still upgrades
// by assuming "in"; `route:` in front of the action marks a forward rule and a
// `_log` suffix marks a logged one. Anything outside that is skipped rather
// than guessed at, which is what ufw does with it too.
function parseTuple(line, v6) {
  var raw = String(line === undefined || line === null ? "" : line)
  if (!/^###[ \t]*tuple[ \t]*###/.test(raw)) return null

  var comment = ""
  var body = raw
  var commentAt = body.indexOf(" comment=")
  if (commentAt !== -1) {
    comment = decodeComment(body.substring(commentAt + " comment=".length))
    body = body.substring(0, commentAt)
  }

  body = body.replace(/^###[ \t]*tuple[ \t]*###[ \t]*/, "").replace(/^\s+|\s+$/g, "")
  if (body === "") return null

  var fields = body.split(/\s+/)
  if (fields.length < 6 || fields.length > 9) return null

  var direction = "in"
  var interfaceIn = ""
  var interfaceOut = ""
  if (fields.length === 7 || fields.length === 9) {
    var ifaces = fields[fields.length - 1]
    direction = ifaces.split("_")[0]
    if (ifaces.indexOf("_") !== -1) {
      if (ifaces.indexOf("!") !== -1 && /in_\w+/.test(ifaces) && /out_\w+/.test(ifaces)) {
        interfaceIn = ifaces.split("!")[0].substring("in_".length)
        interfaceOut = ifaces.split("!")[1].substring("out_".length)
      } else if (ifaces.indexOf("in_") === 0) {
        interfaceIn = ifaces.substring("in_".length)
      } else if (ifaces.indexOf("out_") === 0) {
        interfaceOut = ifaces.substring("out_".length)
      } else {
        return null
      }
    }
  }

  var action = fields[0]
  var forward = false
  if (action.indexOf(":") !== -1) {
    forward = true
    action = action.split(":")[1]
  }
  var logType = ""
  if (action.indexOf("_") !== -1) {
    var parts = action.split("_")
    action = parts[0]
    logType = parts[1] || ""
  }
  if (action === "") return null

  var dapp = ""
  var sapp = ""
  if (fields.length >= 8) {
    if (fields[6] !== "-") dapp = fields[6].replace(/%20/g, " ")
    if (fields[7] !== "-") sapp = fields[7].replace(/%20/g, " ")
  }

  return {
    action: action,
    logType: logType,
    forward: forward,
    protocol: fields[1],
    dport: fields[2],
    dst: fields[3],
    sport: fields[4],
    src: fields[5],
    dapp: dapp,
    sapp: sapp,
    direction: direction,
    interfaceIn: interfaceIn,
    interfaceOut: interfaceOut,
    comment: comment,
    v6: v6 === true
  }
}

function parseRules(text, v6) {
  var lines = String(text === undefined || text === null ? "" : text).split(/\r?\n/)
  var rules = []
  for (var i = 0; i < lines.length; i++) {
    var rule = parseTuple(lines[i], v6)
    if (rule) rules.push(rule)
  }
  return rules
}

// ---- Rendering, mirroring `ufw status`

function isAnyAddress(address) {
  return address === ANY_V4 || address === ANY_V6
}

// One side of a rule as `ufw status` writes it — the "To" column for dst, the
// "From" column for src. Kept deliberately close to ufw's own get_status():
// a widget that renamed things would make its list impossible to check against
// the command everyone already knows.
function locationFor(rule, which) {
  var isDst = which === "dst"
  var address = isDst ? rule.dst : rule.src
  var port = isDst ? rule.dport : rule.sport
  var app = isDst ? rule.dapp : rule.sapp
  var showProtocol = true

  if (app !== "") {
    showProtocol = false
    port = app
    if (rule.v6 && address === ANY_V6) port += " (v6)"
  }

  var location = isAnyAddress(address) ? "" : address

  if (port !== "any") {
    location = location === "" ? port : location + " " + port
    if (showProtocol && rule.protocol !== "any") location += "/" + rule.protocol
    // A rule with a port but no addresses would otherwise render identically
    // to its v4 twin, and every ufw install has both.
    if (rule.v6 && rule.src === ANY_V6 && rule.dst === ANY_V6 && location.indexOf(" (v6)") === -1)
      location += " (v6)"
  } else if (isAnyAddress(address)) {
    location = "Anywhere"
    if (showProtocol && rule.protocol !== "any" && rule.dst === rule.src && rule.dport === rule.sport)
      location += "/" + rule.protocol
    if (address === ANY_V6) location += " (v6)"
  } else if (showProtocol && rule.protocol !== "any" && rule.dport === rule.sport) {
    location += "/" + rule.protocol
  }

  // Interfaces read relative to the firewall for normal rules and relative to
  // the packet's path for route rules, which is why the two swap sides.
  if (rule.forward) {
    if (!isDst && rule.interfaceIn !== "") location += " on " + rule.interfaceIn
    if (isDst && rule.interfaceOut !== "") location += " on " + rule.interfaceOut
  } else {
    if (isDst && rule.interfaceIn !== "") location += " on " + rule.interfaceIn
    if (!isDst && rule.interfaceOut !== "") location += " on " + rule.interfaceOut
  }

  return location
}

function directionLabel(rule) {
  if (rule.forward) return "FWD"
  return String(rule.direction).toUpperCase()
}

function actionGlyph(action) {
  if (action === "allow") return GLYPH_ALLOW
  if (action === "deny") return GLYPH_DENY
  if (action === "reject") return GLYPH_REJECT
  if (action === "limit") return GLYPH_LIMIT
  return GLYPH_SHIELD
}

function directionGlyph(rule) {
  if (rule.forward) return GLYPH_ROUTED
  return rule.direction === "out" ? GLYPH_OUTBOUND : GLYPH_INBOUND
}

// The identity `ufw status` collapses on: several tuples can come from one
// application profile, and the user added one rule, not four.
//
// A faithful port of ufw's UFWRule.get_app_tuple(), and it has to be faithful
// down to the field order — `ufw delete NUM` counts rows with this exact rule,
// so a key that collapsed one row too many or too few would leave every number
// after it pointing at the wrong rule. The port side falls back to the port
// number when only the other side names an app, and the tail is the pair of
// interfaces when there are any and the bare direction when there are not.
function appTupleKey(rule) {
  if (rule.dapp === "" && rule.sapp === "") return ""

  var key = rule.dapp + " " + rule.dst + " " + rule.sapp + " " + rule.src
  if (rule.dapp === "") key = rule.dport + " " + rule.dst + " " + rule.sapp + " " + rule.src
  if (rule.sapp === "") key = rule.dapp + " " + rule.dst + " " + rule.sport + " " + rule.src

  if (rule.interfaceIn === "" && rule.interfaceOut === "") return key + " " + rule.direction
  if (rule.interfaceIn !== "") key += " in_" + rule.interfaceIn
  if (rule.interfaceOut !== "") key += " out_" + rule.interfaceOut
  return key
}

// A rule as one panel row: what it lets through on top, who it applies to
// underneath. `text` is the same rule written the way `ufw status` would, so
// copying a row gives back something recognisable.
function describeRule(rule, index) {
  var to = locationFor(rule, "dst")
  var from = locationFor(rule, "src")
  var verb = String(rule.action).toUpperCase() + " " + directionLabel(rule)

  var notes = []
  notes.push("from " + from)
  if (rule.logType !== "") notes.push(rule.logType.toLowerCase())
  if (rule.comment !== "") notes.push("# " + rule.comment)

  var removeArgs = deleteArgsFor(rule)

  return {
    key: "rule:" + (rule.v6 ? "6" : "4") + ":" + index,
    label: to,
    verb: verb,
    detail: notes.join("  ·  "),
    glyph: actionGlyph(rule.action),
    directionGlyph: directionGlyph(rule),
    action: rule.action,
    v6: rule.v6 === true,
    text: to + "  " + verb + "  " + from + (rule.comment !== "" ? "  # " + rule.comment : ""),
    // What it would take to remove this row, carried on the row itself so the
    // panel never has to hold the raw tuple.
    deleteArgs: removeArgs,
    deleteCommand: commandText(removeArgs)
  }
}

// Every rule ufw would print, v4 then v6, with application rules collapsed to
// the one entry the user actually added.
function buildRuleRows(v4Text, v6Text) {
  var rules = parseRules(v4Text, false).concat(parseRules(v6Text, true))
  var seenApps = {}
  var rows = []
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i]
    var key = appTupleKey(rule)
    if (key !== "") {
      if (seenApps[key]) continue
      seenApps[key] = true
    }
    rows.push(describeRule(rule, i))
  }
  return rows
}

// ---- Writing rules back out
//
// Everything below turns a rule into the argument list that would create or
// remove it. Two rules govern the whole section, and both are about the fact
// that these words end up in front of `pkexec`:
//
//   1. Arguments are a list, never a string. Nothing here builds a command
//      line, so there is no shell to quote for and nothing a space or a
//      semicolon in a comment could break out of.
//   2. Nothing reaches the list unvalidated. Argument vectors already close
//      the injection hole, but ufw has its own flags, and a field that came
//      back "-f" or "--force" from the panel would be one of them rather than
//      an address. Every value is checked against a shape it must have, and
//      every field rejects a leading dash regardless.

var ACTIONS = ["allow", "deny", "reject", "limit"]
var DIRECTIONS = ["in", "out"]
var PROTOCOLS = ["any", "tcp", "udp"]

// iptables' own ceiling on a multiport match.
var MAX_MULTIPORT = 15
// ufw stores comments in the tuple line; long ones are legal but unreadable
// in a bar panel, and this is the one field with no shape of its own.
var MAX_COMMENT = 128

// ---- The commands that carry no rule
//
// enable, disable and reload are chosen here in source and never touched by
// anything the user typed. They are split into the flags ufw parses off the
// front and the payload that follows, and that split is the whole point:
// isSafeArgument exists to stop a rule field becoming a flag, and it cannot
// tell a `--force` picked from this list apart from a `--force` typed into the
// comment box. Gate the payload, hold the flags to an allowlist, and both
// stay true at once.
//
// They live here rather than as literals in the controller because the suite
// has no QML engine. A constant in this file is something a test can hold to
// the same gate the controller applies; an argument list spelled inline in a
// run() call is not, which is exactly how a refusal aimed at rule fields came
// to stop the firewall being switched on.
var FLAG_ALLOWLIST = ["--force"]

var UFW_COMMANDS = {
  // `--force` skips ufw's "this may disrupt existing ssh connections"
  // question, which has nobody to answer it from behind a pkexec dialog.
  enable: { flags: ["--force"], args: ["enable"] },
  disable: { flags: [], args: ["disable"] },
  reload: { flags: [], args: ["reload"] }
}

// The trusted half of a command, checked anyway. Belt and braces beside a
// constant that is already a literal, but it is what stops run()'s unguarded
// half growing quietly later.
function allFlagsAllowed(flags) {
  if (!flags) return true
  for (var i = 0; i < flags.length; i++) if (!inList(FLAG_ALLOWLIST, flags[i])) return false
  return true
}

function inList(list, value) {
  return list.indexOf(value) >= 0
}

// The blanket rule for every value that becomes an argument. A leading dash is
// the interesting half: ufw parses `--force`, `--dry-run` and `-f` off the
// front of its arguments, so a field allowed to start with one would be
// choosing ufw's flags rather than filling in a rule.
function isSafeArgument(value) {
  var text = String(value === undefined || value === null ? "" : value)
  if (text === "") return false
  if (text.charAt(0) === "-") return false
  for (var i = 0; i < text.length; i++) {
    var code = text.charCodeAt(i)
    if (code < 0x20 || code === 0x7f) return false
  }
  return true
}

// ---- Address validation

function isIPv4Address(text) {
  var parts = String(text).split(".")
  if (parts.length !== 4) return false
  for (var i = 0; i < parts.length; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return false
    // No leading zeros: 010 is 8 to some resolvers and 10 to others, and a
    // firewall rule is the wrong place to find out which.
    if (parts[i].length > 1 && parts[i].charAt(0) === "0") return false
    if (Number(parts[i]) > 255) return false
  }
  return true
}

function isHextetList(parts) {
  for (var i = 0; i < parts.length; i++) {
    if (!/^[0-9A-Fa-f]{1,4}$/.test(parts[i])) return false
  }
  return true
}

function splitHextets(section) {
  if (section === "") return []
  var parts = section.split(":")
  // An empty group here means a stray colon; `::` was already taken out.
  for (var i = 0; i < parts.length; i++) if (parts[i] === "") return null
  return isHextetList(parts) ? parts : null
}

function isIPv6Address(text) {
  var raw = String(text)
  // A zone index (fe80::1%wlan0) is a local-interface concept that ufw's rule
  // files have nowhere to put.
  if (raw === "" || raw.length > 45 || raw.indexOf("%") !== -1) return false
  if (!/^[0-9A-Fa-f:.]+$/.test(raw) || raw.indexOf(":") === -1) return false

  // A dotted tail is an embedded IPv4 address, which occupies two hextets.
  var body = raw
  var lastColon = body.lastIndexOf(":")
  var tail = body.substring(lastColon + 1)
  if (tail.indexOf(".") !== -1) {
    if (!isIPv4Address(tail)) return false
    body = body.substring(0, lastColon + 1) + "0:0"
  }

  var halves = body.split("::")
  if (halves.length > 2) return false
  if (halves.length === 2) {
    var head = splitHextets(halves[0])
    var rest = splitHextets(halves[1])
    if (head === null || rest === null) return false
    // `::` stands for at least one omitted group, so the two halves together
    // can never account for all eight.
    return head.length + rest.length <= 7
  }
  var groups = splitHextets(body)
  return groups !== null && groups.length === 8
}

// An address as the panel accepts it: blank and "any" both mean Anywhere,
// anything else is an address or a CIDR block. Hostnames are refused rather
// than resolved — ufw stores what it is given, and a name that resolves
// differently later would silently be a different rule.
function validateAddress(text) {
  var raw = String(text === undefined || text === null ? "" : text).replace(/^\s+|\s+$/g, "")
  if (raw === "" || raw.toLowerCase() === "any" || raw.toLowerCase() === "anywhere")
    return { value: "", v6: false, error: "" }
  if (!isSafeArgument(raw)) return { value: "", v6: false, error: "That is not an address." }

  var address = raw
  var prefix = null
  var slash = raw.indexOf("/")
  if (slash !== -1) {
    address = raw.substring(0, slash)
    var suffix = raw.substring(slash + 1)
    if (!/^\d{1,3}$/.test(suffix)) return { value: "", v6: false, error: "The part after / must be a prefix length." }
    prefix = Number(suffix)
  }

  if (isIPv4Address(address)) {
    if (prefix !== null && prefix > 32) return { value: "", v6: false, error: "An IPv4 prefix cannot be longer than /32." }
    return { value: raw, v6: false, error: "" }
  }
  if (isIPv6Address(address)) {
    if (prefix !== null && prefix > 128) return { value: "", v6: false, error: "An IPv6 prefix cannot be longer than /128." }
    return { value: raw, v6: true, error: "" }
  }
  return { value: "", v6: false, error: "Not an IP address or CIDR block." }
}

// ---- Port validation

function validateSinglePort(text) {
  if (!/^\d{1,5}$/.test(text)) return -1
  var port = Number(text)
  if (port < 1 || port > 65535) return -1
  return port
}

// A port as ufw writes them: one number, a `low:high` range, or a
// comma-separated list. The list and the range are both multiport matches,
// which iptables will only do over tcp or udp — so the protocol is part of
// deciding whether a port is valid at all.
function validatePort(text, protocol) {
  var raw = String(text === undefined || text === null ? "" : text).replace(/^\s+|\s+$/g, "")
  if (raw === "") return { value: "", error: "" }
  if (!isSafeArgument(raw)) return { value: "", error: "That is not a port." }

  var items = raw.split(",")
  if (items.length > MAX_MULTIPORT)
    return { value: "", error: "At most " + MAX_MULTIPORT + " ports in one rule." }

  var multi = items.length > 1
  for (var i = 0; i < items.length; i++) {
    var item = items[i]
    if (item === "") return { value: "", error: "Empty entry in the port list." }
    if (item.indexOf(":") !== -1) {
      multi = true
      var ends = item.split(":")
      if (ends.length !== 2) return { value: "", error: "A range is written low:high." }
      var low = validateSinglePort(ends[0])
      var high = validateSinglePort(ends[1])
      if (low < 0 || high < 0) return { value: "", error: "Ports run from 1 to 65535." }
      if (low > high) return { value: "", error: "The range starts above where it ends." }
    } else if (validateSinglePort(item) < 0) {
      return { value: "", error: "Ports run from 1 to 65535." }
    }
  }

  if (multi && protocol !== "tcp" && protocol !== "udp")
    return { value: "", error: "Several ports at once needs TCP or UDP." }

  return { value: raw, error: "" }
}

// ---- Comment validation

// ufw stores the comment hex-encoded, so almost anything survives the round
// trip — except an apostrophe, which its own parser refuses outright. The
// length cap is ours: a comment is a note to the next person reading the
// list, and one that does not fit in the panel is not one.
function validateComment(text) {
  var raw = String(text === undefined || text === null ? "" : text).replace(/^\s+|\s+$/g, "")
  if (raw === "") return { value: "", error: "" }
  if (raw.indexOf("'") !== -1) return { value: "", error: "ufw will not take an apostrophe in a comment." }
  if (!isSafeArgument(raw)) return { value: "", error: raw.charAt(0) === "-" ? "A comment cannot start with a dash." : "A comment cannot hold control characters." }
  if (raw.length > MAX_COMMENT) return { value: "", error: "Comments stop at " + MAX_COMMENT + " characters." }
  return { value: raw, error: "" }
}

// ---- Building the add command

// A rule as the panel describes it, turned into ufw's own arguments. Returns
// the first thing that is wrong instead of a half-built command, so the caller
// can put the message where the user is looking and disable the button.
//
// Two shapes come out, and they are the two ufw itself writes: the short form
// for the common "open this port to everyone" rule, and the long form as soon
// as a source address is involved.
function buildAddArgs(input) {
  var spec = input || {}

  var action = String(spec.action === undefined || spec.action === null ? "" : spec.action).toLowerCase()
  if (!inList(ACTIONS, action)) return { args: [], error: "Pick what the rule does." }

  var direction = String(spec.direction === undefined || spec.direction === null ? "in" : spec.direction).toLowerCase()
  if (!inList(DIRECTIONS, direction)) return { args: [], error: "Pick a direction." }

  var protocol = String(spec.protocol === undefined || spec.protocol === null ? "any" : spec.protocol).toLowerCase()
  if (!inList(PROTOCOLS, protocol)) return { args: [], error: "Pick a protocol." }

  var port = validatePort(spec.port, protocol)
  if (port.error !== "") return { args: [], error: port.error }

  var from = validateAddress(spec.from)
  if (from.error !== "") return { args: [], error: from.error }

  var comment = validateComment(spec.comment)
  if (comment.error !== "") return { args: [], error: comment.error }

  // A rule with neither a port nor a source is a rule about everything, which
  // is what the default policies are for. Refusing it here keeps a stray Enter
  // from quietly overriding them.
  if (port.value === "" && from.value === "")
    return { args: [], error: "Give it a port, an address, or both." }

  // A port with no protocol is two rules to iptables, which is what ufw does
  // with `allow 22` — worth stating rather than surprising anyone.
  var args = [action]
  if (direction === "out") args.push("out")

  if (from.value === "") {
    // Short form: action, direction, port/proto.
    args.push(protocol === "any" ? port.value : port.value + "/" + protocol)
  } else {
    args.push("from", from.value, "to", "any")
    if (port.value !== "") args.push("port", port.value)
    if (protocol !== "any") args.push("proto", protocol)
  }

  if (comment.value !== "") args.push("comment", comment.value)

  return allArgsSafe(args) ? { args: args, error: "" } : { args: [], error: "That rule cannot be written safely." }
}

// The last gate before anything becomes an argument. Every field above has
// already been checked against a shape; this catches the case where a field
// was added later and nobody remembered to.
function allArgsSafe(args) {
  for (var i = 0; i < args.length; i++) if (!isSafeArgument(args[i])) return false
  return true
}

// ---- Building the delete command
//
// A port of ufw's UFWCommandRule.get_command(), which is the only thing that
// knows how to write a stored tuple back out as the rule that made it.
//
// Deleting by rule rather than by number is the whole point. `ufw delete 3`
// means "whatever is third right now", and between reading the file and the
// password dialog coming back, third can be something else — a rule added from
// a terminal, or the firewall reloaded. Naming the rule cannot go wrong that
// way: if it is no longer there, ufw says so and nothing is removed.
//
// The comment is deliberately left off. ufw matches a delete against the
// stored rules on everything but the comment when the delete carries none,
// so leaving it out matches the rule with or without one.
function ruleSpecArgs(rule) {
  var args = [rule.action]
  var anyDst = isAnyAddress(rule.dst)
  var anySrc = isAnyAddress(rule.src)

  if (anyDst && anySrc && rule.sport === "any" && rule.sapp === ""
      && rule.interfaceIn === "" && rule.interfaceOut === "" && rule.dport !== "any") {
    if (rule.direction === "out") args.push("out")
    if (rule.logType !== "") args.push(rule.logType)
    if (rule.dapp !== "") args.push(rule.dapp)
    else args.push(rule.protocol !== "any" ? rule.dport + "/" + rule.protocol : rule.dport)
    return args
  }

  if (rule.interfaceIn !== "") args.push("in", "on", rule.interfaceIn)
  if (rule.interfaceOut !== "") args.push("out", "on", rule.interfaceOut)
  else if (rule.direction === "out") args.push("out")
  if (rule.logType !== "") args.push(rule.logType)

  var placed = false
  var sides = ["src", "dst"]
  for (var i = 0; i < sides.length; i++) {
    var isSrc = sides[i] === "src"
    var location = isSrc ? rule.src : rule.dst
    var port = isSrc ? rule.sport : rule.dport
    var app = isSrc ? rule.sapp : rule.dapp
    if (isAnyAddress(location)) location = "any"
    if (location === "any" && port === "any" && app === "") continue

    args.push(isSrc ? "from" : "to", location)
    placed = true
    if (app !== "") args.push("app", app)
    else if (port !== "any") args.push("port", port)
  }

  // Nothing but an action so far means a rule so broad it has no endpoints;
  // ufw marks that as the long form with an explicit "to any".
  if (!placed && rule.interfaceIn === "" && rule.interfaceOut === "") args.push("to", "any")

  if (rule.protocol !== "any" && rule.dapp === "" && rule.sapp === "") args.push("proto", rule.protocol)

  return args
}

function deleteArgsFor(rule) {
  var spec = ruleSpecArgs(rule)
  // The tuple came out of a root-owned file, so this is belt and braces — but
  // it is the same braces the add form wears, and a rules file that had been
  // tampered with is exactly when it would matter. An empty list is the
  // panel's signal to offer no delete button for the row at all.
  if (!allArgsSafe(spec)) return []
  // `ufw delete NUM` is the un-routed spelling; a forward rule is deleted the
  // way it was written, with `route` in front.
  return (rule.forward ? ["route", "delete"] : ["delete"]).concat(spec)
}

// How many rows one delete command would take out. ufw keeps the IPv4 and the
// IPv6 halves of a rule in separate files and shows them as separate rows, but
// a rule written without an address is one rule to ufw and comes out of both —
// so a confirmation that only mentioned the row that was clicked would be
// telling half the truth.
function matchingDeleteCount(rows, row) {
  if (!row || !row.deleteCommand) return 0
  var count = 0
  for (var i = 0; i < rows.length; i++) {
    if (rows[i] && rows[i].deleteCommand === row.deleteCommand) count += 1
  }
  return count
}

// The command as a person would type it — for the confirmation dialog and for
// the preview under the add form. Display only: what actually runs is the
// argument list, and this is what that list means.
function commandText(args) {
  var parts = ["ufw"]
  for (var i = 0; i < args.length; i++) {
    var arg = String(args[i])
    parts.push(/[\s'"$`\\]/.test(arg) ? "'" + arg.replace(/'/g, "'\\''") + "'" : arg)
  }
  return parts.join(" ")
}

// ---- Summaries

function statusWord(installed, enabled) {
  if (!installed) return "not installed"
  if (enabled === null || enabled === undefined) return "unknown"
  return enabled ? "active" : "inactive"
}

function pluralize(count, word) {
  return count + " " + word + (count === 1 ? "" : "s")
}

// The bar tooltip. Short enough to read at a glance and specific enough to be
// worth hovering: the state, and how much is riding on it.
function barSummary(installed, enabled, ruleCount) {
  if (!installed) return "ufw is not installed"
  if (enabled === null || enabled === undefined) return "status unknown"
  if (!enabled) return "inactive — nothing is being filtered"
  return "active — " + pluralize(ruleCount, "rule")
}

function policySummary(defaults) {
  if (!defaults) return ""
  return "in " + defaults.input + "  ·  out " + defaults.output + "  ·  routed " + defaults.forward
}

if (typeof module !== "undefined") {
  module.exports = {
    parseEnabled: parseEnabled,
    parseLogLevel: parseLogLevel,
    policyWord: policyWord,
    parseDefaults: parseDefaults,
    decodeComment: decodeComment,
    parseTuple: parseTuple,
    parseRules: parseRules,
    locationFor: locationFor,
    directionLabel: directionLabel,
    actionGlyph: actionGlyph,
    describeRule: describeRule,
    buildRuleRows: buildRuleRows,
    statusWord: statusWord,
    barSummary: barSummary,
    policySummary: policySummary,
    appTupleKey: appTupleKey,
    isSafeArgument: isSafeArgument,
    isIPv4Address: isIPv4Address,
    isIPv6Address: isIPv6Address,
    validateAddress: validateAddress,
    validatePort: validatePort,
    validateComment: validateComment,
    buildAddArgs: buildAddArgs,
    ruleSpecArgs: ruleSpecArgs,
    deleteArgsFor: deleteArgsFor,
    commandText: commandText,
    matchingDeleteCount: matchingDeleteCount,
    allArgsSafe: allArgsSafe,
    allFlagsAllowed: allFlagsAllowed,
    UFW_COMMANDS: UFW_COMMANDS,
    FLAG_ALLOWLIST: FLAG_ALLOWLIST,
    ACTIONS: ACTIONS,
    DIRECTIONS: DIRECTIONS,
    PROTOCOLS: PROTOCOLS
  }
}
