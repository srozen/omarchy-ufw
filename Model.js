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
function appTupleKey(rule) {
  return rule.dapp + " " + rule.dst + " " + rule.sapp + " " + rule.src
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

  return {
    key: "rule:" + (rule.v6 ? "6" : "4") + ":" + index,
    label: to,
    verb: verb,
    detail: notes.join("  ·  "),
    glyph: actionGlyph(rule.action),
    directionGlyph: directionGlyph(rule),
    action: rule.action,
    v6: rule.v6 === true,
    text: to + "  " + verb + "  " + from + (rule.comment !== "" ? "  # " + rule.comment : "")
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
    if (rule.dapp !== "" || rule.sapp !== "") {
      var key = appTupleKey(rule)
      if (seenApps[key]) continue
      seenApps[key] = true
    }
    rows.push(describeRule(rule, i))
  }
  return rows
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
    policySummary: policySummary
  }
}
