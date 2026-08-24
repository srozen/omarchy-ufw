// Tests for Model.js — the pure half of the widget, where every assumption
// about ufw's on-disk format is written down.
//
//   node tests/run.js
//
// No dependencies and no framework: the plugin ships no package.json and is
// not built, so a suite that needed installing would not get run.
//
// Model.js is a QML `.pragma library`, which has no module system — just
// top-level declarations. Running it in this realm's global scope turns those
// into globals, which is as close to importing it as node gets without a QML
// engine.

const fs = require("fs")
const path = require("path")
const vm = require("vm")
const assert = require("assert")

const source = fs.readFileSync(path.join(__dirname, "..", "Model.js"), "utf8")
  .replace(/^\s*\.pragma\s+library\s*$/m, "")

const before = new Set(Object.getOwnPropertyNames(globalThis))
vm.runInThisContext(source, { filename: "Model.js" })

const Model = {}
for (const name of Object.getOwnPropertyNames(globalThis)) {
  if (!before.has(name)) Model[name] = globalThis[name]
}

let passed = 0
const failures = []

function test(name, fn) {
  try {
    fn()
    passed += 1
  } catch (error) {
    failures.push({ name, error })
  }
}

// ---- ufw.conf

test("ENABLED=yes reads as enabled", () => {
  assert.strictEqual(Model.parseEnabled("# comment\nENABLED=yes\nLOGLEVEL=low\n"), true)
})

test("ENABLED=no reads as disabled", () => {
  assert.strictEqual(Model.parseEnabled("ENABLED=no\n"), false)
})

test("quoted and spaced values still parse", () => {
  assert.strictEqual(Model.parseEnabled('ENABLED = "YES"\n'), true)
})

test("a commented-out ENABLED is not a value", () => {
  assert.strictEqual(Model.parseEnabled("#ENABLED=yes\n"), null)
})

test("a missing key is unknown, not off", () => {
  assert.strictEqual(Model.parseEnabled("LOGLEVEL=low\n"), null)
})

test("log level is lowercased", () => {
  assert.strictEqual(Model.parseLogLevel("LOGLEVEL=LOW\n"), "low")
  assert.strictEqual(Model.parseLogLevel(""), "")
})

// ---- /etc/default/ufw

test("iptables targets become ufw's own words", () => {
  const defaults = Model.parseDefaults([
    'IPV6=yes',
    'DEFAULT_INPUT_POLICY="DROP"',
    'DEFAULT_OUTPUT_POLICY="ACCEPT"',
    'DEFAULT_FORWARD_POLICY="REJECT"'
  ].join("\n"))
  assert.deepStrictEqual(defaults, { input: "deny", output: "allow", forward: "reject", ipv6: true })
})

test("IPV6=no is the only thing that turns v6 off", () => {
  assert.strictEqual(Model.parseDefaults("IPV6=no\n").ipv6, false)
  assert.strictEqual(Model.parseDefaults("").ipv6, true)
})

test("an empty file falls back to ufw's install defaults", () => {
  assert.deepStrictEqual(Model.parseDefaults(""), { input: "deny", output: "allow", forward: "deny", ipv6: true })
})

// ---- Tuples

test("a plain port rule parses", () => {
  const rule = Model.parseTuple("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", false)
  assert.strictEqual(rule.action, "allow")
  assert.strictEqual(rule.protocol, "tcp")
  assert.strictEqual(rule.dport, "22")
  assert.strictEqual(rule.direction, "in")
  assert.strictEqual(rule.forward, false)
  assert.strictEqual(rule.logType, "")
  assert.strictEqual(rule.comment, "")
})

test("a logged action keeps the action and the log type apart", () => {
  const rule = Model.parseTuple("### tuple ### deny_log tcp 23 0.0.0.0/0 any 0.0.0.0/0 in", false)
  assert.strictEqual(rule.action, "deny")
  assert.strictEqual(rule.logType, "log")
})

test("route: marks a forward rule", () => {
  const rule = Model.parseTuple("### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1", false)
  assert.strictEqual(rule.forward, true)
  assert.strictEqual(rule.action, "allow")
  assert.strictEqual(rule.interfaceIn, "eth0")
  assert.strictEqual(rule.interfaceOut, "eth1")
})

test("a single interface lands on the right side", () => {
  const inbound = Model.parseTuple("### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_wlan0", false)
  assert.strictEqual(inbound.interfaceIn, "wlan0")
  assert.strictEqual(inbound.interfaceOut, "")
  assert.strictEqual(inbound.direction, "in")

  const outbound = Model.parseTuple("### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 out_wlan0", false)
  assert.strictEqual(outbound.interfaceOut, "wlan0")
  assert.strictEqual(outbound.direction, "out")
})

test("the six-field legacy format is assumed inbound", () => {
  const rule = Model.parseTuple("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0", false)
  assert.strictEqual(rule.direction, "in")
  assert.strictEqual(rule.dapp, "")
})

test("application rules carry their profile names", () => {
  const rule = Model.parseTuple("### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 CUPS%20Web - in", false)
  assert.strictEqual(rule.dapp, "CUPS Web")
  assert.strictEqual(rule.sapp, "")
})

test("comments are hex-decoded", () => {
  const rule = Model.parseTuple(
    "### tuple ### allow udp 53 172.17.0.1 any 172.16.0.0/12 in comment=616c6c6f772d646f636b65722d646e73", false)
  assert.strictEqual(rule.comment, "allow-docker-dns")
})

test("a UTF-8 comment survives the round trip", () => {
  // "café" as UTF-8 bytes.
  assert.strictEqual(Model.decodeComment("636166c3a9"), "café")
})

test("malformed tuples are skipped rather than guessed at", () => {
  assert.strictEqual(Model.parseTuple("### tuple ### allow tcp 22", false), null)
  assert.strictEqual(Model.parseTuple("-A ufw-user-input -p tcp --dport 22 -j ACCEPT", false), null)
  assert.strictEqual(Model.parseTuple("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 sideways_eth0", false), null)
})

test("parseRules picks the tuples out of a real rules file", () => {
  const file = [
    "*filter",
    ":ufw-user-input - [0:0]",
    "### RULES ###",
    "",
    "### tuple ### allow udp 53317 0.0.0.0/0 any 0.0.0.0/0 in",
    "-A ufw-user-input -p udp --dport 53317 -j ACCEPT",
    "",
    "### tuple ### allow tcp 53317 0.0.0.0/0 any 0.0.0.0/0 in",
    "-A ufw-user-input -p tcp --dport 53317 -j ACCEPT",
    "### END RULES ###",
    "COMMIT"
  ].join("\n")
  const rules = Model.parseRules(file, false)
  assert.strictEqual(rules.length, 2)
  assert.strictEqual(rules[0].protocol, "udp")
  assert.strictEqual(rules[1].protocol, "tcp")
})

// ---- Rendering, checked against what `ufw status` prints

function ruleFrom(line, v6) {
  return Model.parseTuple(line, v6)
}

test("a port rule reads as ufw prints it", () => {
  const rule = ruleFrom("### tuple ### allow tcp 53317 0.0.0.0/0 any 0.0.0.0/0 in", false)
  assert.strictEqual(Model.locationFor(rule, "dst"), "53317/tcp")
  assert.strictEqual(Model.locationFor(rule, "src"), "Anywhere")
})

test("the v6 twin of a port rule is marked, so the two are told apart", () => {
  const rule = ruleFrom("### tuple ### allow tcp 53317 ::/0 any ::/0 in", true)
  assert.strictEqual(Model.locationFor(rule, "dst"), "53317/tcp (v6)")
  assert.strictEqual(Model.locationFor(rule, "src"), "Anywhere (v6)")
})

test("addresses show on both sides", () => {
  const rule = ruleFrom(
    "### tuple ### allow udp 53 172.17.0.1 any 172.16.0.0/12 in comment=616c6c6f772d646f636b65722d646e73", false)
  assert.strictEqual(Model.locationFor(rule, "dst"), "172.17.0.1 53/udp")
  assert.strictEqual(Model.locationFor(rule, "src"), "172.16.0.0/12")
})

test("an application rule shows the profile name instead of a port", () => {
  const rule = ruleFrom("### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 CUPS - in", false)
  assert.strictEqual(Model.locationFor(rule, "dst"), "CUPS")
})

test("an interface is reported relative to the firewall on a normal rule", () => {
  const rule = ruleFrom("### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_eth0", false)
  assert.strictEqual(Model.locationFor(rule, "dst"), "80/tcp on eth0")
})

test("an interface is reported relative to the packet on a route rule", () => {
  const rule = ruleFrom("### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1", false)
  assert.strictEqual(Model.locationFor(rule, "src"), "Anywhere on eth0")
  assert.strictEqual(Model.locationFor(rule, "dst"), "Anywhere on eth1")
})

test("direction labels match ufw's", () => {
  assert.strictEqual(Model.directionLabel(ruleFrom("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", false)), "IN")
  assert.strictEqual(Model.directionLabel(ruleFrom("### tuple ### deny tcp 25 0.0.0.0/0 any 0.0.0.0/0 out", false)), "OUT")
  assert.strictEqual(Model.directionLabel(ruleFrom("### tuple ### route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0", false)), "FWD")
})

test("a row carries the action, the sides, and the comment", () => {
  const rule = ruleFrom(
    "### tuple ### allow udp 53 172.17.0.1 any 172.16.0.0/12 in comment=616c6c6f772d646f636b65722d646e73", false)
  const row = Model.describeRule(rule, 0)
  assert.strictEqual(row.label, "172.17.0.1 53/udp")
  assert.strictEqual(row.verb, "ALLOW IN")
  assert.ok(row.detail.includes("from 172.16.0.0/12"))
  assert.ok(row.detail.includes("# allow-docker-dns"))
  assert.strictEqual(row.text, "172.17.0.1 53/udp  ALLOW IN  172.16.0.0/12  # allow-docker-dns")
})

test("each action gets its own glyph, and an unknown one falls back", () => {
  const glyphs = ["allow", "deny", "reject", "limit"].map(Model.actionGlyph)
  assert.strictEqual(new Set(glyphs).size, 4)
  assert.strictEqual(Model.actionGlyph("nonsense"), Model.GLYPH_SHIELD)
})

test("the bar glyphs are the wall, with and without its fire", () => {
  assert.strictEqual(Model.GLYPH_WALL_FIRE, String.fromCodePoint(0xF1A11))
  assert.strictEqual(Model.GLYPH_WALL, String.fromCodePoint(0xF07FE))
  assert.notStrictEqual(Model.GLYPH_WALL_FIRE, Model.GLYPH_WALL)
})

// ---- Whole-file assembly

test("v4 rules come before v6 rules, and both are kept", () => {
  const v4 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"
  const v6 = "### tuple ### allow tcp 22 ::/0 any ::/0 in"
  const rows = Model.buildRuleRows(v4, v6)
  assert.strictEqual(rows.length, 2)
  assert.strictEqual(rows[0].v6, false)
  assert.strictEqual(rows[1].v6, true)
  assert.strictEqual(rows[0].label, "22/tcp")
  assert.strictEqual(rows[1].label, "22/tcp (v6)")
})

test("row keys are unique, so the copy marker cannot land on two rows", () => {
  const v4 = [
    "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
    "### tuple ### allow udp 22 0.0.0.0/0 any 0.0.0.0/0 in"
  ].join("\n")
  const v6 = "### tuple ### allow tcp 22 ::/0 any ::/0 in"
  const rows = Model.buildRuleRows(v4, v6)
  assert.strictEqual(new Set(rows.map(r => r.key)).size, rows.length)
})

test("one application profile is one row, however many tuples it wrote", () => {
  const v4 = [
    "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 WWW%20Full - in",
    "### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 WWW%20Full - in"
  ].join("\n")
  const rows = Model.buildRuleRows(v4, "")
  assert.strictEqual(rows.length, 1)
  assert.strictEqual(rows[0].label, "WWW Full")
})

test("an empty rules file is no rules, not an error", () => {
  assert.deepStrictEqual(Model.buildRuleRows("", ""), [])
})

// ---- Summaries

test("the bar tooltip separates off from unknown", () => {
  assert.strictEqual(Model.barSummary(false, null, 0), "ufw is not installed")
  assert.strictEqual(Model.barSummary(true, null, 0), "status unknown")
  assert.strictEqual(Model.barSummary(true, false, 4), "inactive — nothing is being filtered")
  assert.strictEqual(Model.barSummary(true, true, 4), "active — 4 rules")
  assert.strictEqual(Model.barSummary(true, true, 1), "active — 1 rule")
})

test("status words match what the panel says", () => {
  assert.strictEqual(Model.statusWord(false, null), "not installed")
  assert.strictEqual(Model.statusWord(true, null), "unknown")
  assert.strictEqual(Model.statusWord(true, true), "active")
  assert.strictEqual(Model.statusWord(true, false), "inactive")
})

test("the policy summary names all three defaults", () => {
  const summary = Model.policySummary({ input: "deny", output: "allow", forward: "deny" })
  assert.ok(summary.includes("in deny"))
  assert.ok(summary.includes("out allow"))
  assert.ok(summary.includes("routed deny"))
})

// ---- App-rule collapsing, which is also the numbering `ufw delete NUM` uses

test("an app tuple key carries the direction when there is no interface", () => {
  const rule = Model.parseTuple("### tuple ### allow tcp 631 0.0.0.0/0 any 0.0.0.0/0 CUPS - in", false)
  assert.strictEqual(Model.appTupleKey(rule), "CUPS 0.0.0.0/0 any 0.0.0.0/0 in")
})

test("a non-app rule has no app key at all", () => {
  const rule = Model.parseTuple("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", false)
  assert.strictEqual(Model.appTupleKey(rule), "")
})

test("the port stands in for the side that names no app", () => {
  const rule = Model.parseTuple("### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 - Samba in", false)
  assert.strictEqual(Model.appTupleKey(rule), "any 0.0.0.0/0 Samba 0.0.0.0/0 in")
})

test("interfaces replace the direction in the key", () => {
  const rule = Model.parseTuple("### tuple ### allow tcp 631 0.0.0.0/0 any 0.0.0.0/0 CUPS - in_eth0", false)
  assert.strictEqual(Model.appTupleKey(rule), "CUPS 0.0.0.0/0 any 0.0.0.0/0 in_eth0")
})

test("the same app in and out stays two rules", () => {
  // ufw counts these as two rows, so `ufw delete 2` means the second one. A
  // key that collapsed them would put every later number off by one.
  const rows = Model.buildRuleRows([
    "### tuple ### allow tcp 631 0.0.0.0/0 any 0.0.0.0/0 CUPS - in",
    "### tuple ### allow udp 631 0.0.0.0/0 any 0.0.0.0/0 CUPS - in",
    "### tuple ### allow tcp 631 0.0.0.0/0 any 0.0.0.0/0 CUPS - out"
  ].join("\n"), "")
  assert.strictEqual(rows.length, 2)
  assert.strictEqual(rows[0].verb, "ALLOW IN")
  assert.strictEqual(rows[1].verb, "ALLOW OUT")
})

// ---- Writing a rule back out, checked against ufw's own get_command()

function specFor(line, v6) {
  return Model.commandText(Model.deleteArgsFor(Model.parseTuple(line, v6 === true)))
}

test("a plain port rule comes back as the short form", () => {
  assert.strictEqual(specFor("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"),
    "ufw delete allow 22/tcp")
})

test("no protocol means no slash", () => {
  assert.strictEqual(specFor("### tuple ### limit any 22 0.0.0.0/0 any 0.0.0.0/0 in"),
    "ufw delete limit 22")
})

test("an outgoing rule says so before the port", () => {
  assert.strictEqual(specFor("### tuple ### deny udp 53 0.0.0.0/0 any 0.0.0.0/0 out"),
    "ufw delete deny out 53/udp")
})

test("a log type is part of the rule, so it is part of the delete", () => {
  // ufw only removes a rule whose action *and* log type match, so dropping
  // `log` here would delete nothing.
  assert.strictEqual(specFor("### tuple ### allow_log tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"),
    "ufw delete allow log 22/tcp")
})

test("a source address forces the long form", () => {
  assert.strictEqual(specFor("### tuple ### allow udp 53 172.17.0.1 any 172.16.0.0/12 in"),
    "ufw delete allow from 172.16.0.0/12 to 172.17.0.1 port 53 proto udp")
})

test("an app rule is deleted by its profile name", () => {
  assert.strictEqual(specFor("### tuple ### allow tcp 631 0.0.0.0/0 any 0.0.0.0/0 CUPS - in"),
    "ufw delete allow CUPS")
})

test("a profile name with a space stays one argument", () => {
  const args = Model.deleteArgsFor(Model.parseTuple(
    "### tuple ### allow tcp 137 0.0.0.0/0 any 0.0.0.0/0 Samba%20Server - in", false))
  assert.deepStrictEqual(args, ["delete", "allow", "Samba Server"])
  assert.strictEqual(Model.commandText(args), "ufw delete allow 'Samba Server'")
})

test("a rule with nothing but an interface keeps the interface clause", () => {
  assert.strictEqual(specFor("### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_wg0"),
    "ufw delete allow in on wg0")
})

test("a rule about everything is marked as the long form with 'to any'", () => {
  assert.strictEqual(specFor("### tuple ### deny any any 0.0.0.0/0 any 0.0.0.0/0 in"),
    "ufw delete deny to any")
})

test("a forward rule is deleted the way it was written, through route", () => {
  assert.strictEqual(specFor("### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1"),
    "ufw route delete allow in on eth0 out on eth1 to any port 80 proto tcp")
})

test("the comment is left off so a rule matches with or without one", () => {
  // ufw removes a rule whose only difference is the comment, but only when the
  // delete carries none — so carrying one would make this fussier, not safer.
  const args = Model.deleteArgsFor(Model.parseTuple(
    "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=6c616220626f78", false))
  assert.deepStrictEqual(args, ["delete", "allow", "22/tcp"])
})

test("every row carries the command that would remove it", () => {
  const rows = Model.buildRuleRows("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", "")
  assert.deepStrictEqual(rows[0].deleteArgs, ["delete", "allow", "22/tcp"])
  assert.strictEqual(rows[0].deleteCommand, "ufw delete allow 22/tcp")
})

test("the v4 and v6 halves of one rule share a delete command", () => {
  const rows = Model.buildRuleRows(
    "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
    "### tuple ### allow tcp 22 ::/0 any ::/0 in")
  assert.strictEqual(rows.length, 2)
  assert.strictEqual(rows[0].deleteCommand, rows[1].deleteCommand)
  assert.strictEqual(Model.matchingDeleteCount(rows, rows[0]), 2)
})

test("a rule with an address of its own stands alone", () => {
  const rows = Model.buildRuleRows("### tuple ### allow udp 53 172.17.0.1 any 172.16.0.0/12 in", "")
  assert.strictEqual(Model.matchingDeleteCount(rows, rows[0]), 1)
})

// ---- Addresses

test("IPv4 addresses and blocks are accepted", () => {
  for (const value of ["10.0.0.5", "192.168.1.0/24", "0.0.0.0/0", "255.255.255.255"]) {
    assert.strictEqual(Model.validateAddress(value).error, "", value)
    assert.strictEqual(Model.validateAddress(value).value, value)
  }
})

test("blank and 'any' both mean Anywhere", () => {
  for (const value of ["", "   ", "any", "Anywhere"]) {
    const result = Model.validateAddress(value)
    assert.strictEqual(result.error, "")
    assert.strictEqual(result.value, "")
  }
})

test("IPv6 addresses, blocks and embedded v4 are accepted", () => {
  for (const value of ["::1", "::", "fe80::/10", "2001:db8::8a2e:370:7334",
                       "2001:0db8:0000:0000:0000:ff00:0042:8329", "::ffff:192.168.0.1",
                       "1:2:3:4:5:6:1.2.3.4"]) {
    const result = Model.validateAddress(value)
    assert.strictEqual(result.error, "", value + " -> " + result.error)
    assert.strictEqual(result.v6, true, value)
  }
})

test("hostnames are refused rather than resolved", () => {
  // A name that resolves differently tomorrow would silently be a different
  // rule; ufw stores what it is given, so only literals get in.
  assert.notStrictEqual(Model.validateAddress("example.com").error, "")
  assert.notStrictEqual(Model.validateAddress("localhost").error, "")
})

test("malformed addresses are refused", () => {
  for (const value of ["1.2.3.256", "1.2.3", "1.2.3.4.5", "010.1.1.1", "1::2::3", ":::",
                       "fe80::1%wlan0", "12345::", "gg::1", "1.2.3.4 8.8.8.8"]) {
    assert.notStrictEqual(Model.validateAddress(value).error, "", value)
  }
})

test("prefix lengths are checked against the family", () => {
  assert.notStrictEqual(Model.validateAddress("10.0.0.0/33").error, "")
  assert.notStrictEqual(Model.validateAddress("fe80::/129").error, "")
  assert.strictEqual(Model.validateAddress("10.0.0.0/32").error, "")
  assert.strictEqual(Model.validateAddress("fe80::/128").error, "")
})

// ---- Ports

test("single ports, ranges and lists are accepted", () => {
  assert.strictEqual(Model.validatePort("22", "tcp").value, "22")
  assert.strictEqual(Model.validatePort("8000:8010", "tcp").value, "8000:8010")
  assert.strictEqual(Model.validatePort("80,443", "tcp").value, "80,443")
  assert.strictEqual(Model.validatePort("", "tcp").value, "")
})

test("ports outside 1-65535 are refused", () => {
  for (const value of ["0", "65536", "-1", "99999", "22a"]) {
    assert.notStrictEqual(Model.validatePort(value, "tcp").error, "", value)
  }
})

test("a backwards range is refused", () => {
  assert.notStrictEqual(Model.validatePort("900:100", "tcp").error, "")
})

test("several ports at once need a protocol iptables can multiport", () => {
  assert.notStrictEqual(Model.validatePort("80,443", "any").error, "")
  assert.notStrictEqual(Model.validatePort("8000:8010", "any").error, "")
  assert.strictEqual(Model.validatePort("80,443", "udp").error, "")
})

test("a port list longer than iptables allows is refused", () => {
  const many = Array.from({ length: 16 }, (_, i) => String(i + 1)).join(",")
  assert.notStrictEqual(Model.validatePort(many, "tcp").error, "")
})

// ---- Comments

test("an ordinary comment survives", () => {
  assert.strictEqual(Model.validateComment("  home lan  ").value, "home lan")
})

test("ufw's own refusal of apostrophes is mirrored here", () => {
  assert.notStrictEqual(Model.validateComment("it's mine").error, "")
})

test("control characters and over-long comments are refused", () => {
  assert.notStrictEqual(Model.validateComment("one\ntwo").error, "")
  assert.notStrictEqual(Model.validateComment("x".repeat(129)).error, "")
  assert.strictEqual(Model.validateComment("x".repeat(128)).error, "")
})

// ---- The guard every argument passes

test("a leading dash is refused wherever it appears", () => {
  // Argument lists close the injection hole; this closes the one left over,
  // where a field would be read as one of ufw's own flags.
  assert.strictEqual(Model.isSafeArgument("--force"), false)
  assert.strictEqual(Model.isSafeArgument("-f"), false)
  assert.strictEqual(Model.isSafeArgument("--dry-run"), false)
  assert.strictEqual(Model.isSafeArgument("22/tcp"), true)
  assert.strictEqual(Model.isSafeArgument("Samba Server"), true)
  assert.strictEqual(Model.isSafeArgument(""), false)
  assert.strictEqual(Model.isSafeArgument("a\nb"), false)
})

test("allArgsSafe refuses a list with one bad entry", () => {
  assert.strictEqual(Model.allArgsSafe(["delete", "allow", "22/tcp"]), true)
  assert.strictEqual(Model.allArgsSafe(["delete", "allow", "--force"]), false)
})

// ---- Building the add command

function addArgs(spec) {
  return Model.buildAddArgs(spec).args
}

test("the common case is the short form", () => {
  assert.deepStrictEqual(addArgs({ action: "allow", direction: "in", protocol: "tcp", port: "22" }),
    ["allow", "22/tcp"])
})

test("any protocol drops the slash", () => {
  assert.deepStrictEqual(addArgs({ action: "allow", direction: "in", protocol: "any", port: "22" }),
    ["allow", "22"])
})

test("outgoing appears where ufw puts it", () => {
  assert.deepStrictEqual(addArgs({ action: "deny", direction: "out", protocol: "udp", port: "53" }),
    ["deny", "out", "53/udp"])
})

test("a source address switches to the long form", () => {
  assert.deepStrictEqual(
    addArgs({ action: "allow", direction: "in", protocol: "tcp", port: "22", from: "192.168.1.0/24" }),
    ["allow", "from", "192.168.1.0/24", "to", "any", "port", "22", "proto", "tcp"])
})

test("an address with no port is still a rule", () => {
  assert.deepStrictEqual(addArgs({ action: "deny", direction: "in", protocol: "any", from: "10.0.0.5" }),
    ["deny", "from", "10.0.0.5", "to", "any"])
})

test("a comment rides along as its own argument", () => {
  assert.deepStrictEqual(
    addArgs({ action: "allow", direction: "in", protocol: "tcp", port: "22", comment: "lan ssh" }),
    ["allow", "22/tcp", "comment", "lan ssh"])
})

test("a rule with neither a port nor an address is refused", () => {
  // That is a rule about all traffic, which is what the default policies are
  // for -- and a stray Enter should not be able to override them.
  assert.notStrictEqual(Model.buildAddArgs({ action: "allow", direction: "in", protocol: "any" }).error, "")
})

test("unknown actions, directions and protocols are refused", () => {
  const base = { direction: "in", protocol: "tcp", port: "22" }
  assert.notStrictEqual(Model.buildAddArgs(Object.assign({}, base, { action: "reset" })).error, "")
  assert.notStrictEqual(Model.buildAddArgs(Object.assign({}, base, { action: "" })).error, "")
  assert.notStrictEqual(Model.buildAddArgs(Object.assign({}, base, { action: "allow", direction: "sideways" })).error, "")
  assert.notStrictEqual(Model.buildAddArgs(Object.assign({}, base, { action: "allow", protocol: "icmp" })).error, "")
})

test("nothing that looks like a flag survives any field", () => {
  const base = { action: "allow", direction: "in", protocol: "tcp", port: "22" }
  for (const field of ["port", "from", "comment"]) {
    const spec = Object.assign({}, base)
    spec[field] = "--force"
    const built = Model.buildAddArgs(spec)
    assert.notStrictEqual(built.error, "", field)
    assert.deepStrictEqual(built.args, [], field)
  }
})

test("a failed build hands back no arguments at all", () => {
  // The controller runs whatever list it is given, so a half-built one must
  // never come back alongside an error.
  const built = Model.buildAddArgs({ action: "allow", direction: "in", protocol: "tcp", port: "70000" })
  assert.notStrictEqual(built.error, "")
  assert.deepStrictEqual(built.args, [])
})

test("the preview is the command the argument list means", () => {
  const built = Model.buildAddArgs({
    action: "limit", direction: "out", protocol: "udp", port: "8000:8010", comment: "test rig"
  })
  assert.strictEqual(built.error, "")
  assert.strictEqual(Model.commandText(built.args), "ufw limit out 8000:8010/udp comment 'test rig'")
})

test("commandText quotes for the eye without changing the list", () => {
  assert.strictEqual(Model.commandText(["delete", "allow", "Samba Server"]),
    "ufw delete allow 'Samba Server'")
  assert.strictEqual(Model.commandText(["allow", "22/tcp"]), "ufw allow 22/tcp")
})

// ---- Report


for (const { name, error } of failures) {
  console.error(`FAIL  ${name}`)
  console.error(`      ${error && error.message ? error.message : error}`)
}
console.log(`${passed} passed, ${failures.length} failed`)
process.exit(failures.length === 0 ? 0 : 1)
