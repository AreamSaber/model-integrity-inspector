# M6 SQLite private staging component

## Scope and current checkpoint

This unit adds only `internal/integrity/privatefile/sqlite_staging*.go` and this
note. Existing `Read` / `WriteNew`, repository, application, crypto, manifest,
database migrations, and maintenance protocols are unchanged. This is a private
temporary-file bridge for SQLite's path-based destination open. It is not a
database online-backup coordinator, authenticated backup, restore, or M6-05
completion, and has no HTTP surface.

The shared and both native implementations are compiling. Windows actual SQLite
and native regression results are recorded below. Linux/amd64 cross-compilation
and Linux-target lint passed; no Linux native execution is claimed. The component
is frozen for root review, not formally approved.

## API and publication boundary

`WithSQLiteStaging(ctx, parent, SQLiteLimits, build, consume) (Receipt, error)`
creates a random private workspace and an existing empty `snapshot.db`. The
explicit limits are database bytes (1..1 TiB), workspace bytes (at least the DB
limit and at most 2 TiB), and a timeout (positive, at most 24h). Main and all
sidecars share the workspace budget. These are resource policies, not measured
database or deployment capacities.

`SQLiteTarget.URI`, `ROURI`, and `Check` are only valid during synchronous build.
Copies share private state; all inspections, limit failures, and cancellation are
sticky. URI is fixed `file:` / `mode=rw`; ROURI is fixed `mode=ro` with
`_pragma=query_only(1)`. Neither exposes a native handle. Formatting and JSON
protect both pointer and value forms. URI strings cannot themselves be revoked:
trusted build code must not retain them or start detached work.

Build owns real SQLite completion, all rows/statements/connections being closed,
final journal consolidation, and a separately closed genuinely read-only
integrity/foreign-key validation. SQLite's `TxOptions.ReadOnly` alone is not such
an open. Staging deliberately does not claim that arbitrary bytes are a valid
SQLite database.

After build, targets are invalidated. Native sealing syncs and binds the main
file; the consumer gets only the existing bounded 64 KiB reader. Success requires
complete finite consumption, real final EOF, native identity/size/mtime/permissions
and directory rechecks, every close/cleanup, and the final context check.
Any failure returns a zero receipt; success returns `Published=false`. Generic
callback panics/errors are closed classifications, never original exception data.
The consumer must withhold external publication until the complete call returns
success: cleanup or final native checks can fail after all bytes were consumed.

## Native path and scratch-file policy

Linux walks each ancestor with no-follow opens. Owners are root/current UID;
group/other writable ancestors are refused unless the trusted-owned parent is
sticky and the next real child is also trusted-owned. Final parent/workspace are
0700 and the main file is created 0600. Storage filesystem policy is unchanged.
The final dirfd is for native creation/identity/cleanup, not a claim that SQLite
writes through a dirfd. The pinned SQLite VFS resolves `/proc/self/fd` symlinks;
that spelling would not provide stable-dirfd pathname opens. Cross-UID confinement
comes from the entire trusted ancestor chain. Same UID/root remain trusted, but
observed path/identity changes refuse success and speculative deletion.

Linux metadata inspection does not open/close main or shared-memory sidecar fds:
doing so can release the process's existing SQLite POSIX locks. It uses `fstatat`
and requires regular single-link private same-device sidecars instead.

Windows walks and retains every no-reparse ancestor with deny-delete sharing.
Ancestors may allow read/traverse or only adding new children, but not outsider
modification/deletion/replacement of the existing chain, owner, DACL, attributes,
or EA. Generic write/all are not broadly allowed. The final private parent and
created workspace/main/sidecars retain the stricter existing data ACL boundary.
The workspace is born with private inheritable DACLs so SQLite-created sidecars
are private from birth.

The sole additional ancestor-owner case is the locally resolved, exact fixed
TrustedInstaller SID, only at the actual OS volume root. It does not grant this
owner to a workspace, parent, DB, or sidecar, and does not broadly trust arbitrary
`NT SERVICE` names. Treating that narrowly scoped principal as part of the OS
trust boundary is an engineering decision; Microsoft's documentation describes
its role in [Windows Resource Protection](https://learn.microsoft.com/en-us/windows/win32/wfp/about-windows-file-protection),
not approval of this implementation. Directory add-child and delete-child rights
are separate [native access rights](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants).

Actual local ACL inspection found the ordinary D: root and default Temp unsafe
for this stronger path-open boundary. Production does not relocate or repair a
caller path. Tests create only a new private profile child after checking its
ancestor chain; no existing system/user ACL is changed. Fixture deletion checks
its absolute scope, pinned chain, and originally captured file identity.

Windows main guard requests READ/WRITE without DELETE and shares READ/WRITE.
SQLite's fixed VFS does not share DELETE, so even a READ/WRITE-shared old guard
would conflict if it still requested DELETE. Existing WriteNew remains share0.
After SQLite closes, sealing reacquires the same main identity exclusively with
DELETE access; surviving SQLite readers and writers prevent this transition.
The workspace directory keeps its own original DELETE-capable handle throughout.

Only main and the three exact `snapshot.db-journal`, `-wal`, `-shm` names are
recognized. A sealed workspace must contain only the nonempty main file; leftover
sidecars are a failure, not silently omitted content. Unknown or replaced entries
are never recursively deleted. Cleanup removes only identity-matching owned
entries; a failure can leave a private orphan and must not return success.

## Journal generations: red test and constrained correction

The original implementation remembered each sidecar name's first identity for
the entire operation. Root review identified that a normal DELETE journal can be
removed and later recreated by a second transaction.

- First test run: 0.105s failed in identity-allocation setup, not production. It
  used `os.Stat`/`os.SameFile` across deletion; that is not a sound identity pin
  (Windows may resolve identity lazily and Linux may immediately reuse an inode).
- Revised actual SQLite test: 0.115s failed with `MI_PRIVATE_FILE_UNSAFE` at the
  second legitimate generation. It captures native identity immediately and
  pins the old object using a known test-only hardlink outside the workspace.
  Each production Check sees a single-link journal or its genuine absence. The
  pin prevents allocator reuse, is not production permission to use hardlinks,
  and is identity-checked before its final test-owned cleanup.
- The correction retires a sidecar generation only after a complete successful
  directory/file/permission/size inspection explicitly observes that name absent.
  A changed identity without such an absence observation is still refused.
  Failed/partial checks do not retire generations; cleanup only owns the current
  recorded generation.
- The same actual SQLite counterexample passed after the correction (0.112s).
  The subsequent complete Windows staging/native suite passed (0.493s), including
  the direct-replacement negative that never observes an intervening absence.

An individual SQLite backup normally holds one destination transaction across
its Steps, but legitimate configuration/finalization transactions can surround
that backup. This component must not assume there will only ever be one journal.
No real online-backup coordinator has been implemented by this unit.

## Executed evidence

All commands used the existing exact Go 1.26.7 toolchain. No shared PostgreSQL or
project-schema fixture was used. Actual SQLite tests used only new test-owned
private files; no production data or existing directory ACL was modified.

- Windows compile-only: `go test ./internal/integrity/privatefile -run '^$'`,
  PASS 0.090s. This preceded runtime validation.
- Windows native synthetic-file suite, `-run '^TestSQLiteWindowsNative' -count=1`:
  ten top-level tests, PASS 0.165s, then 0.163s after strengthening test-owned
  fixture cleanup. Native tests exercise real Windows opens with SQLite's exact
  share flags, not the SQLite API itself.
- Journal counterexample: setup failure 0.105s; actual production red 0.115s;
  same revised test after the generation correction PASS 0.112s.
- Complete new Windows suite,
  `go test ./internal/integrity/privatefile -run '^TestSQLite(Staging|WindowsNative)' -count=1 -v`:
  eighteen top-level tests, **PASS 0.493s**. It includes actual SQLite write and
  separately closed read-only validation; main-file receipt/hash and capability
  invalidation; callback panic/error, partial reads, cancellation and final mtime
  mutation; sticky main/workspace size failures; real WAL/SHM consolidation and
  PERSIST-journal omission rejection; actual `mode=rw` missing-file refusal;
  legitimate journal generations; unknown-entry compound failure and no wrong
  deletion; native guard/share, ancestor ACL, inheritance and identity cases.
- Final Windows package lint: **0 issues**.
- Final Linux/amd64 package lint: **0 issues**; final `CGO_ENABLED=0 go test -c`
  cross-compilation passed. Initial Linux lint found two int-to-uint64 UID
  conversions and two intentional test ACL/path warnings. Production now compares
  signed int64 UIDs; only the exact test-owned negative operations have local
  explanations. No lint rule was disabled globally.

The shared DB time slot was explicitly returned after that single complete
runtime suite; no additional database rounds were queued.

Root integration review subsequently read all new native/shared production and
tests, including the actual journal-generation counterexample. The complete
Windows privatefile package (new and existing tests), three rounds, passed in
3.359s; root package lint also reported 0 issues. This is additional Windows
evidence, not Linux execution or online-backup completion.

Frozen files: `sqlite_staging.go`, `sqlite_staging_linux.go`,
`sqlite_staging_windows.go`, `sqlite_staging_unsupported.go`,
`sqlite_staging_test.go`, `sqlite_staging_linux_test.go`,
`sqlite_staging_windows_test.go`, and this note.

## Remaining integration limits

Linux tests include real sticky/non-sticky ancestor policy and replacement cases, but
cross-building those tests is not Linux runtime evidence. Actual Linux CI must
execute them on an already allowed filesystem; policy is not relaxed for overlay.

This component checks budgets between cooperative operations and after completion;
it does not impose a kernel write quota or forcibly interrupt an in-flight SQLite
Step. A future coordinator must use bounded positive Step counts, bounded busy
handling, correct source snapshot semantics, and an explicit single finalizer.
In pinned modernc v1.58.0, Commit invokes native finish and returns the destination
connection only on success. Non-DONE finish can roll back and still return nil;
that never means a completed snapshot. The error branch, like Finish, discards
its internal destination Close error. A future integration must not promise all
failed handles were released, or mistake a cleanup orphan for an available backup.

No project DB/PG fixture, Git operation, dependency change, or formal approval
occurred in this component's implementation.
