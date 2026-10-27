#!/bin/bash
# Seatbelt captureDenials (learning mode) and the mxc-exec-mac --audit shortcut.
#
# Each mode is checked against the workload's own result as well as the
# report, so a report that lists the read cannot hide a mode that stopped
# changing enforcement.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/seatbelt_common.sh
. "$SCRIPT_DIR/lib/seatbelt_common.sh"

[ -x /usr/bin/python3 ] || fail "/usr/bin/python3 is required to read the reports"

# Under /private/tmp so the logged path matches what we assert on (/tmp is a
# symlink). No config grants this directory, so the read is a default deny.
TESTDIR="$(mktemp -d /private/tmp/mxc-seatbelt-capture.XXXXXX)"
trap 'rm -rf "$TESTDIR" "$SEATBELT_TMP"' EXIT
mkdir -p "$TESTDIR/ungranted" "$TESTDIR/out"
echo "CAPTURE_SECRET_CONTENT" >"$TESTDIR/ungranted/secret.txt"
chmod -R a+rX "$TESTDIR"
SECRET="$TESTDIR/ungranted/secret.txt"

# Report path from the pointer line mxc-exec-mac prints on stderr.
REPORT=""
read_pointer() {
    local label="$1" line
    line="$(grep -m1 '^{"type":"captureDenials"' <<<"$OUT")" ||
        fail "$label (no captureDenials pointer line)" "$OUT"
    REPORT="$(/usr/bin/python3 -c 'import json,sys; print(json.loads(sys.argv[1])["outputPath"])' "$line")" ||
        fail "$label (unreadable pointer line)" "$OUT"
    [ -f "$REPORT" ] || fail "$label (report $REPORT was not written)" "$OUT"
    pass "$label"
}

# Assert the report lists RESOURCE with the given type and access.
expect_listed() {
    local label="$1" type="$2" resource="$3" access="$4"
    /usr/bin/python3 - "$REPORT" "$type" "$resource" "$access" <<'EOF' ||
import json, sys
path, rtype, resource, access = sys.argv[1:]
doc = json.load(open(path))
sys.exit(0 if any(
    d["resourceType"] == rtype and d["resource"] == resource and d["accessType"] == access
    for d in doc["denials"]) else 1)
EOF
        fail "$label (no $type/$access entry for $resource)" "$(cat "$REPORT")"
    pass "$label"
}

# --- block mode (the default) -----------------------------------------------

run_config "$(render seatbelt_capture_denials_block.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/denials.json")"
expect_ok "block mode still enforces the policy" "CAPTURE_READ_BLOCKED"
expect_absent "block mode does not leak the file" "CAPTURE_SECRET_CONTENT"
read_pointer "block mode writes a report"
expect_listed "block mode lists the denied read" file "$SECRET" read

case "$REPORT" in
    "$TESTDIR/out/denials."*.json) pass "the report name gets a per-run identifier" ;;
    *) fail "the report was not written next to outputPath with a run identifier: $REPORT" ;;
esac

VERBOSE="${REPORT%.json}.verbose.json"
[ -f "$VERBOSE" ] || fail "the verbose report was not written: $VERBOSE"
/usr/bin/python3 - "$VERBOSE" <<'EOF' || fail "the verbose report is not a v6 seatbelt document" "$(head -c 2000 "$VERBOSE")"
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["version"] == 6
assert doc["signatures"]
assert all(s["signature"]["provider"] == "seatbelt" for s in doc["signatures"])
EOF
pass "the verbose report is a v6 seatbelt document"

# --- allow mode --------------------------------------------------------------

run_config "$(render seatbelt_capture_denials_allow.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/denials.json")"
expect_ok "allow mode lets the default-denied read through" "CAPTURE_SECRET_CONTENT"
expect_marker "allow mode warns that the policy was not enforced" "ran the workload without enforcing"
read_pointer "allow mode writes a report"
expect_listed "allow mode still lists the read" file "$SECRET" read

# --- --audit -----------------------------------------------------------------

run_config "$(render seatbelt_capture_denials_audit.json TESTDIR "$TESTDIR")" --audit
expect_ok "--audit runs the workload in allow mode" "CAPTURE_SECRET_CONTENT"
read_pointer "--audit writes a report"
expect_listed "--audit lists the read" file "$SECRET" read
rm -f "$REPORT" "${REPORT%.json}.verbose.json"

# --- UI denials under guiAccess ---------------------------------------------

# ui.clipboard=none must survive the guiAccess blanket Mach grant, and the
# report must attribute the blocked pasteboard to UI rather than "other".
run_config "$(render seatbelt_capture_denials_gui_clipboard_none.json OUTPUT "$TESTDIR/out/gui.json")"
expect_ok "the pasteboard stays blocked under guiAccess" "CLIPBOARD_BLOCKED"
read_pointer "the guiAccess run writes a report"
/usr/bin/python3 - "$REPORT" <<'EOF' || fail "the pasteboard denial is not reported as ui" "$(cat "$REPORT")"
import json, sys
doc = json.load(open(sys.argv[1]))
assert any(d["resourceType"] == "ui" and "com.apple.pasteboard" in d["resource"]
           for d in doc["denials"])
EOF
pass "the pasteboard denial is reported as ui"

# --- a real GUI app: which Mach services and IOKit drivers it needs ----------

# A minimal AppKit app (JavaScript for Automation) that opens a window. Only
# services every Mac has, VMs included, are asserted; the reports list more.
mkdir -p "$TESTDIR/app"
cat >"$TESTDIR/app/window.js" <<'EOF'
ObjC.import('AppKit');
var app = $.NSApplication.sharedApplication;
app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
var w = $.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer(
    $.NSMakeRect(0, 0, 200, 100), $.NSWindowStyleMaskTitled, $.NSBackingStoreBuffered, false);
w.orderFrontRegardless;
w.display;
$.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.5));
console.log(w.windowNumber > 0 ? "GUI_WINDOW_OK" : "GUI_WINDOW_FAILED");
w.close;
EOF
chmod -R a+rX "$TESTDIR/app"

GUI_MACH="mach-lookup:com.apple.CARenderServer"
GUI_IOKIT="iokit-open-user-client:IOSurfaceRootUserClient"

# Assert the verbose report shows guiAccess's blanket grant serving OP TARGET.
expect_granted() {
    local label="$1" op="$2" target="$3"
    /usr/bin/python3 - "${REPORT%.json}.verbose.json" "$op" "$target" <<'EOF' ||
import json, sys
path, op, target = sys.argv[1:]
doc = json.load(open(path))
sys.exit(0 if any(
    s["signature"]["eventName"] == op
    and dict(s["signature"]["properties"]).get("target") == target
    and dict(s["signature"]["properties"]).get("decision") == "allowGrant"
    for s in doc["signatures"]) else 1)
EOF
        fail "$label (no allowGrant $op $target in the verbose report)" "$(head -c 4000 "${REPORT%.json}.verbose.json")"
    pass "$label"
}

# Without guiAccess, ui.disable=false still reaches WindowServer, but drawing
# the window needs services only guiAccess grants. The report names them.
run_config "$(render seatbelt_capture_denials_gui_app_no_gui_access.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/gui_off.json")"
expect_marker_any "the GUI app ran without guiAccess" "GUI_WINDOW_OK" "GUI_WINDOW_FAILED"
read_pointer "the GUI app run without guiAccess writes a report"
expect_listed "without guiAccess the Core Animation lookup is reported blocked" other "$GUI_MACH" unknown
expect_listed "without guiAccess the IOSurface driver is reported blocked" other "$GUI_IOKIT" unknown

# With guiAccess the same requests succeed and are reported as grant uses,
# not as denials.
run_config "$(render seatbelt_capture_denials_gui_app.json TESTDIR "$TESTDIR" OUTPUT "$TESTDIR/out/gui_on.json")"
expect_ok "the GUI app ran with guiAccess" "GUI_WINDOW_OK"
read_pointer "the GUI app run with guiAccess writes a report"
expect_granted "guiAccess reports the Core Animation lookup it served" mach-lookup com.apple.CARenderServer
expect_granted "guiAccess reports the IOSurface driver it opened" iokit-open-user-client IOSurfaceRootUserClient
for resource in "$GUI_MACH" "$GUI_IOKIT"; do
    grep -qF "\"$resource\"" "$REPORT" && fail "a granted request is listed as denied: $resource" "$(cat "$REPORT")"
done
pass "granted requests are not listed as denials"

# --- rejections --------------------------------------------------------------

expect_rejected "captureDenials cannot be combined with profileOverride" \
    seatbelt_capture_denials_profile_override.json "cannot be combined with seatbelt.profileOverride" \
    "CAPTURE_OVERRIDE_RAN"
expect_rejected "--audit refuses a config that already sets captureDenials" \
    seatbelt_capture_denials_block.json "cannot be combined with seatbelt.captureDenials" "CAPTURE_READ" --audit

summary "Seatbelt captureDenials"
