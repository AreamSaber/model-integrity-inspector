# Confined S1 report artifacts

`Open` accepts an absolute directory, creates only its final component when absent,
and refuses broad existing permissions, symbolic links, Windows reparse points,
nonregular artifacts and artifacts with multiple hard links. The directory is
pinned by an opened handle and an `os.Root` capability. Windows permits only the
current service identity, SYSTEM and trusted builtin Administrators to own or
access the directory/artifacts; new directories inherit current-identity and
SYSTEM ACLs only. Unix requires current-user/root ownership, no group/other
permissions, and no executable artifact. Existing container paths must satisfy
these requirements; this package never repairs global ACLs.

`Put` accepts organization ID, closed format (`json`/`html`) and at most 16 MiB.
It stages a restricted file, syncs its bytes and publishes a content-addressed
hard link without overwriting an existing file. `Read` derives the name from the
typed reference, opens without following links, checks actual handle rights,
identity, length and SHA-256 before returning bytes. Paths, endpoints, request
bodies and secret storage are not inputs. This package alone does not authorize
a download: the service must resolve the reference from authorized database
metadata and audit/revalidate the current session and grants.

## Database / filesystem boundary

The report Worker first freezes a bounded validated S1 input in the database,
then writes the artifact, then publishes its hashes in the leased Job completion
transaction with an audit receipt. Retries reuse the frozen generation timestamp
and exact input. A database rollback after the file write can leave an orphan;
that file has no authorized ready record and cannot be downloaded. Ordinary
retries after that boundary are tested and byte-stable.

This is not a cross-resource atomic transaction. A crash between hard-link
publication and removing the staging link can leave two links; reads then fail
closed until confined maintenance repairs/removes the orphan. No directory-wide
cleanup, total-disk quota or retention policy is implemented here. Windows lacks
a portable directory fsync, so sudden power loss may require artifact repair even
after file Sync. Missing/corrupt files do not remove the published Run result.

The current report schema explicitly has `review_state: not_included` and null
review: it does not claim the Run has never been reviewed. Adding a frozen human
review snapshot requires a new report schema/revision, not rewriting an artifact.
Content hash excludes the content_hash field; final JSON and HTML each have an
independent file hash. See the report kernel README for canonicalization rules.

Tests cover real files, current Windows ACLs, junction traversal, hard links,
tampering, cancellation and bounds. Windows symbolic-link tests may skip when the
host lacks symbolic-link privilege; junction rejection is tested separately.
Unix-specific tests require a Unix runner; cross-compilation is not runtime proof.
These development tests are not a security approval or calibrated model result.
