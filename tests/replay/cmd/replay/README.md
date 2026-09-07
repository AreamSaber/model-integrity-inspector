# Development-only offline replay CLI

This command consumes a separately exported, signed **development capture**, explicit development trust documents, and a supported rule artifact. It runs the real offline adapter → local tokenizer → features → runtime pipeline. It never accepts an endpoint, database, label file, calibration flag, stdin, or a caller-supplied normalized response/token count.

The signature and `source_publication_hash` remain controller statements. They do not prove official-provider provenance, database completion to an independent verifier, blind acceptance, or release authority. The output remains development-only and uncalibrated C/D. A1/B1 are not completion of M5-06 publication/retirement.

## Invocation

Build from the repository with the frozen Go toolchain on PATH:

```text
go build -o replay.exe ./tests/replay/cmd/replay
```

Pass all six local file/hash arguments. This example describes the interface; it does not claim that a production export or these files already exist:

```text
replay.exe --capture D:\private-replay\capture.json --rule D:\private-replay\rule.json --rule-sha256 <trusted-64-lowercase-hex> --capture-public-key-file D:\private-replay\capture-public.json --manifest-key-file D:\private-replay\manifest-key.json --output D:\private-replay\prediction.json --timeout 30s
```

`--timeout` defaults to 30s and must be 1–120s. Flags cannot repeat. No positional arguments are accepted. Errors print one closed `MI_REPLAY_*` code, not the input arguments, paths, body, nonce, key, underlying OS error, or prediction. Success prints `MI_REPLAY_OK_DEVELOPMENT_ONLY`; the S1 prediction is written only to the explicit output file. Exit codes: 0 success, 2 invalid arguments, 130 cooperative cancellation, 1 other failure.

## Explicit trust roots

- `localfile.NewManifestSigner()` creates a **new independent random development-only ProbeMAC key**. `EncodeDevelopmentManifestKey` is its explicit S2 export operation. It cannot export an application `secret.KeyRing` or raw master key. The generator and replay verifier must use that same separate signer. Destroy the signer and clear serialized key bytes after their bounded use.
- `EncodeDevelopmentCapturePublicKey` exports a development Ed25519 verification document with an explicit `dev-*` key ID. The public key and ID are operator-selected file inputs, never taken as a trust root from the capture itself.
- Both documents use bounded (2048-byte), closed, **exact canonical JSON** schemas. A raw 32-byte master, unknown/duplicate/case-aliased/omitted fields, different purpose/version, trailing bytes, or noncanonical encoding is rejected. A valid schema cannot authenticate where an operator obtained a key; controlled generation and private handling remain necessary.
- The command does not generate keys or export production data. The controlled Worker/TLS exporter is a separate test-side capability, subject to final database-settlement verification and decoded-content secret scanning. Nothing here bypasses that boundary.

## Files, resource limits, and cancellation

The supported OS boundary is Windows and Linux; other platforms fail closed. Paths must be explicit clean **absolute** paths. No URL, UNC, device namespace, ADS, Win32 reserved/trailing-dot alias, symlink, junction/reparse, or hardlink with link count other than one is accepted. Every input, including public keys and rule JSON, must have private permissions: Linux current/root owner and exact 0400/0600; Windows a restricted owner/DACL allowing only the current user, SYSTEM, or Administrators.

- Windows pins the native directory handle, resolves relative names with `OBJ_DONT_REPARSE`, refuses mapped network drives, and opens inputs without write/delete sharing.
- Linux walks directory components using `openat(O_NOFOLLOW)`, opens the final file `O_NONBLOCK`, then verifies regular type, owner, mode, link count, and filesystem type. The filesystem allowlist is ext-family, XFS, Btrfs, tmpfs, overlay, ramfs and F2FS; unknown/NFS/CIFS/FUSE/pseudo-filesystems are rejected. This policy is **not** an OS denied-network proof, including for overlay backing configuration.
- Input sizes: capture ≤24 MiB, rule ≤1 MiB, each trust document ≤2 KiB. Stricter core per-manifest/body/request/batch/sample limits still apply. The full finite file is read from one verified handle and checked again before the core receives only a memory reader. Output ≤4 MiB.
- Cancellation and timeout are cooperative checks around bounded reads, computation, and publication. They cannot forcibly interrupt arbitrary kernel I/O or promise a hard real-time deadline. Pipes/devices and arbitrary `io.Reader` inputs are deliberately excluded. Runtime computational limits remain enforced independently.

The output directory must already exist and be private (Linux owner/root + 0700-equivalent; Windows restricted ACL). After successful computation, a random private temporary file is created exclusively inside the pinned directory, written, synced and checked for cancellation. Windows publishes with handle-relative native rename and `ReplaceIfExists=false`; Linux uses same-directory `linkat` no-replace then removes only its own matching-inode temporary entry. Existing output is never changed. A caught failure/cancellation before publication leaves no partial final file; forced process/OS termination can leave a private temporary file, but no partial final namespace entry. After a successful namespace commit, a durability error may leave the **complete** final output; the command never deletes it to pretend rollback. Windows file flushing plus rename does not claim portable directory fsync/power-loss durability.

## Evidence and limits of this checkpoint

Tests build and start the actual executable for synthetic valid capture → real parser/runtime → deterministic S1 output, changed signing/Manifest keys, malformed or duplicate JSON, raw master rejection, incorrect artifact hash, invalid paths/timeouts, existing-output preservation, and external caller cancellation during process startup. Separate in-process tests cover a canceled context; file tests cancel after writing and syncing the complete temporary file but before atomic publication. Native file tests cover concurrent no-replace publication, links, unsafe permissions and path aliases; symlink creation may be skipped where the OS denies that test capability.

The synthetic CLI fixtures are explicitly not real DB-settlement proofs or acceptance data. The separately reviewed real Worker/TLS fixture tests own that evidence. No system firewall or global network configuration is changed here. **An OS-enforced denied-network executable exercise has not been performed in this checkpoint.** Source/AST inspection or closing the mock server is not a substitute. Linux cross-compilation is not a claim that Linux filesystem tests executed on the Windows development host.
