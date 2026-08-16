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

// ---- Report

for (const { name, error } of failures) {
  console.error(`FAIL  ${name}`)
  console.error(`      ${error && error.message ? error.message : error}`)
}
console.log(`${passed} passed, ${failures.length} failed`)
process.exit(failures.length === 0 ? 0 : 1)
