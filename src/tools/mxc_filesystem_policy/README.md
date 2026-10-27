# Application-package filesystem baseline

`mxc-filesystem-policy` documents directory access supplied by
`ALL_APPLICATION_PACKAGES`, or by `ALL_RESTRICTED_APPLICATION_PACKAGES`.
It emits a JSON fragment using MXC's `filesystem` field names.

**This is documentation, not an executable replacement policy or a process
access check.** Generated `deniedPaths` are exceptions to the selected group's
baseline. They are not explicit MXC denials: explicit policy may independently
grant access to these exceptions, and an applicable explicit policy denial
takes precedence over access supplied by the group.

The utility does not read or merge an MXC request. Native BaseContainer grant
and deny precedence remains separate from this explanatory baseline.

## Build and run

From `src/`, using the repository's pinned Rust toolchain:

```powershell
cargo build --locked --release -p mxc_filesystem_policy

.\target\release\mxc-filesystem-policy.exe `
    --path C:\Windows\WinSxS `
    --out aap-filesystem.json
```

Repeat `--path` for multiple roots. Live collection requires Windows; explicit
roots are resolved to canonical paths. Overlapping roots are scanned once.
Without `--out`, JSON goes to stdout. Counts, provenance, and errors go to stderr.
Fragment files are replaced only after collection, classification, and
verification succeed. Only the supplied roots are covered; paths outside them
are not classified.

When stderr is a terminal, an in-place progress display shows elapsed time,
directory paths processed, unknown paths encountered, queued directories, and
the current path. It uses an activity bar rather than a percentage because the
total directory count is not known in advance. Updates are throttled to ten per
second; inventory loading, generation, and writing also show their current phase.

Progress never goes to stdout and is hidden when stderr is redirected.
Use `--progress never` to disable it, or `--progress always` to force it when
capturing stderr. Forced output without terminal dimensions uses an 80-column
layout. The display is cleared before completion summaries or errors.

For the restricted application-package group:

```powershell
.\target\release\mxc-filesystem-policy.exe `
    --path C:\Windows\WinSxS `
    --principal all-restricted-application-packages
```

A directory tree that is readable except for an inaccessible `InstallTemp`
directory is represented as:

```json
{
  "filesystem": {
    "readwritePaths": [],
    "readonlyPaths": ["C:\\Windows\\WinSxS"],
    "deniedPaths": ["C:\\Windows\\WinSxS\\InstallTemp"]
  }
}
```

## Meaning and limits

- Both explicit and inherited ACEs naming the selected SID are considered in
  DACL order. Inherit-only ACEs do not supply rights on their containing folder.
  Generic rights are expanded to directory rights.

- Read-only means the group has read-and-execute rights without write/delete
  rights. Read-write requires modify rights. The fragment documents these
  categories, not every NTFS permission such as changing ownership or the DACL.
  Partial combinations that do not fit a category cause an error with the path
  and mask; they are not silently widened or converted into denies.

- Rules are emitted where a directory's category changes from its parent's.
  A readable descendant of an ungranted directory can therefore appear beneath
  a baseline deny exception. Volume-root grants do not supply a recursive
  default to children; those children are classified separately.

- Empty, hidden, and system directories are included. In particular, an empty
  directory without a grant remains an exception. There is no `--ignore-empty`
  option for policy documentation.

- The collector does not change ownership, ACLs, privileges, or containment.
  By default, read/enumeration failures, unsupported DACL ACE formats, and nested
  directory reparse points stop generation. Best-effort mode records these
  branches as unknown instead. Unknown paths are not reported as denied.

- This is a selected-group ACE inventory, not an effective-access calculation.
  Other SIDs, including Everyone, null DACLs, the process token, user permissions,
  and explicit policy are not combined into this report.

- Only directories are inventoried. Their files can have different ACLs.
  Broad entries must not be interpreted as proof of every file's accessibility.
  The scan is not an atomic filesystem snapshot; changed ACLs or newly created
  directories require regeneration.

## Best-effort drive scans

Use a mandatory, separate coverage report when scanning roots containing paths
that cannot be inspected:

```powershell
.\target\release\mxc-filesystem-policy.exe `
    --path C:\ `
    --best-effort `
    --report c-drive-aap-coverage.json `
    --save-inventory c-drive-aap-inventory.json `
    --out c-drive-aap-filesystem.json
```

**A partial fragment must be read together with its coverage report.** The report
has `complete: false` and lists unknown paths with reasons. Its unknown entries
qualify broad ancestor grants in the fragment; do not infer access to an unknown
path merely because its ancestor appears in `readonlyPaths` or `readwritePaths`.
Unknown paths are never inserted into `deniedPaths`.

A `subtree` scope means that directory and its descendants were skipped, for
example at a junction or an unreadable branch. A `directory` scope means its
rights could not be classified, but its children were inventoried separately.
Junctions and other directory reparse points are not followed, so a drive scan
does not cross mounted volumes or enter junction cycles.

Best-effort mode returns success when the requested partial export finishes,
prints a `PARTIAL` warning when coverage is incomplete, and preserves unknowns
in the saved inventory. Replaying an incomplete inventory also requires
`--best-effort --report FILE`. Strict mode remains the default.

## Save and replay an inventory

```powershell
.\target\release\mxc-filesystem-policy.exe `
    --path C:\Windows\WinSxS `
    --save-inventory aap-inventory.json `
    --out aap-filesystem.json

.\target\release\mxc-filesystem-policy.exe `
    --inventory aap-inventory.json `
    --out aap-filesystem-replayed.json
```

The inventory records the selected principal and each directory's path, parent,
volume-root status, and decided allow/deny masks. Replay is available on other
platforms and does not read the recorded paths. A supplied `--principal` must
match the saved principal. Inventory format version 2 records unknown branches;
version 1 inventories remain readable. These formats are tool-specific, not MXC
request contracts. A collected inventory is saved even if subsequent strict
classification finds unrepresentable rights, so those masks can be inspected
without rescanning. A failed strict collection is not saved.

The generator validates the tree and replays its compact rules against every
inventoried directory before emitting output. Lists are sorted by path.
`serde`/`serde_json` provide the inventory and fragment formats, `clap` provides
the CLI, `windows` supplies the native collection APIs, and `tempfile` provides
atomic output replacement. On Unix, `libc` supplies terminal dimensions for
offline replay progress.

## Checks

From `src/`:

```powershell
cargo fmt -p mxc_filesystem_policy -- --check
cargo clippy -p mxc_filesystem_policy --all-targets -- -D warnings
cargo test -p mxc_filesystem_policy
```

Workspace Cargo tests include the command-line scenarios on every platform.
Windows integration tests create disposable directories with controlled DACLs,
exercise native collection for both principals, preserve empty and nested
exceptions, and check that unsupported rights cannot replace an existing output.
A best-effort fixture creates a temporary junction cycle and checks that it is
recorded as unknown rather than followed. A sandbox that prohibits junction
creation cannot run that fixture; the read-only collector itself creates no
junctions.
