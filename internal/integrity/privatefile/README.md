# Private streaming local files

`Read` and `WriteNew` are trusted internal capabilities for future backup work.
They are not HTTP endpoints, generic upload handlers, archive parsers, encryption,
database snapshots or completed backup/restore functionality.

## Contract

Callers supply an absolute canonical local path, an existing private parent,
`Limits{MaxBytes, Timeout}`, and a synchronous callback receiving only `io.Reader`
or `io.Writer` plus a derived context. Limits are mandatory and capped at 1 TiB
and 24 hours. These are input/resource policies, not measured database capacities.
Empty files are rejected. No native file or close capability is exposed.

The implementation processes at most 64 KiB per I/O operation and hashes bytes
incrementally. Reader success requires consuming the entire initial finite file,
final EOF, matching handle identity/size/mtime, safe permissions and the same
parent directory identity. Reader callbacks must withhold any external publication
until `Read` succeeds: bytes already consumed cannot be retracted, and this API
does not authenticate them or provide an atomic snapshot against a trusted owner
concurrently modifying the same inode. Backup consumers need authenticated
envelopes, expected hashes and actual database snapshot mechanisms separately.

Errors are fixed classification codes. Underlying filesystem and callback errors
are never returned verbatim. A swallowed stream error still fails the operation.
Returned callbacks' reader/writer capabilities are invalidated, including on a
panic; arbitrary callback code and blocking kernel I/O cannot be forcibly stopped.
Callbacks must remain cooperative and must not retain wrappers or create detached
work. Context checks occur before/after callback, per chunk, and before publication.

Writes create a restrictive random same-directory staging file, then sync and
publish with native no-replace semantics. The `Receipt` has only Size, SHA256 and
Published. Before publication errors do not delete or replace any destination;
cleanup only attempts this invocation's created staging entry/handle. A cleanup
failure or same-UID staging tampering can leave private orphans. After publication,
sync, close, deadline or parent-replacement failure returns `Published=true`; the
complete published output is never deleted as error rollback. Callers must not
equate an error with absence of output and must gate application-level availability
on their own final authorization/audit/receipt transaction.

## Platform policy

- Windows: fixed DOS drive, actual NTFS handle with persistent ACL support; no
  UNC/device/ADS/trailing-dot/8.3/substituted-drive/reparse aliases. Native names
  are case-insensitive. Owner/control/read rights are restricted to the current
  user, SYSTEM and trusted local Administrators. Creation grants current user and
  SYSTEM from the start; inputs share only reads, directories disallow deletion.
  Publication uses `NtSetInformationFile` with ReplaceIfExists=false, not os.Rename.
  Parent-directory `FILE_DELETE_CHILD` is a sensitive right too: granting it to
  another trustee is rejected even when the file's own DACL is private.
- Linux: no-follow directory walk and regular single-link handles, owner/root
  ownership and private modes; supported local types are ext4, XFS, Btrfs, tmpfs,
  ramfs and F2FS. NFS/CIFS/FUSE/overlay/unknown and pseudo filesystems fail closed.
  Publication requires `renameat2(RENAME_NOREPLACE)` and directory fsync; no
  unsupported fallback silently overwrites a name.
- Other OSes fail closed. Windows has no portable directory fsync, so successful
  publication is not an unconditional power-loss warranty. tmpfs/ramfs contents
  are ephemeral. Filesystem-type policy is not an OS network-denial proof.

The host owner/root/Administrators remain trusted. In particular, Linux cannot
provide an atomic unlink-by-handle primitive against a malicious same-UID actor
that races within its own private directory; staging entry identity is checked
before cleanup and publication. Such an actor can also replace the binary or read
process memory, and is outside the cross-user confinement boundary.

## Evidence boundary

Windows tests exercise a real 32 MiB+17-byte stream with independent hashes and
bounded allocations, concurrent no-replace writers, cancellation/deadline and
swallowed-error cases, returned capability invalidation, partial reads, hardlinks,
ACL broadening, mandatory native junctions, and post-publication failure receipts.
The Windows ACL regression includes Everyone granted only `FILE_DELETE_CHILD`
(0x40): both read and write must reject that parent, publish nothing new and leave
the existing input unchanged. This case failed against the original rights mask
and passed after including directory child-deletion authority in that mask.
This is component evidence, not large-database capacity or disaster-recovery proof.

Windows runners can supply an 8.3 alias in TMP/TEMP. The Windows test fixture
canonicalizes only its own freshly created `t.TempDir` using its actual handle,
then independently opens the canonical name and verifies the same volume/file
identity before returning it. This is test setup, not production path repair.
A real `GetShortPathName` regression sets TMP/TEMP to an allocated short base and
uses a child test's first TempDir: normal canonical fixture read/write must work,
while direct short-alias read/write must still fail without publishing a file.
If the volume allocates no short alias, the test records that boolean; canonical
fixture checks still run, but that run is not 8.3 rejection evidence. Locally this
reproduced immediate `MI_PRIVATE_FILE_UNSAFE` before the fixture fix. Matching a
remote CI symptom does not establish its unique cause; the next Windows CI run
must confirm whether any other failure remains. Diagnostic messages use fixed
stage labels and booleans, not temporary/user paths or credentials.

Linux tests additionally exercise actual symlinks/FIFO, directory rename/replacement,
input mutation, staging replacement and post-publication directory sync failure.
Tests never skip for an unsafe filesystem. Docker build layers may use overlay;
in that case the same mandatory tests use a verified tmpfs `/dev/shm` private
directory. They run sequentially and clean each ~32 MiB fixture before the next,
not all at once on Docker's usual 64 MiB shared-memory mount. If no supported local
test filesystem is available, tests fail. This does not validate an overlay or
production backup volume. Cross-compilation alone is not Linux execution evidence.
