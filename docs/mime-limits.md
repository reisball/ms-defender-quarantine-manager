# MIME extraction and parser limits

The original EML remains unchanged. Existing extracted files retain their order,
names and bytes. Whole `message/global` messages and explicitly attached multipart
entities are appended after those legacy files; existing child attachments are
not replaced. RFC822 descendants are still validated without duplicate extraction.
Ordinary multipart bodies do not become attachments.

The extra files are serialized analysis views using the existing
`email.policy.default`, not byte-exact slices of the original wire message.
They share the unchanged 100-attachment and decoded-size limits. A newly included
container can make a previously incomplete extraction reach those limits; it is
then rejected before publication rather than silently omitted. Existing SOAR
`ready` records retain their prepared snapshot without automatic re-export or
attachment backfill. New extraction applies when preparation runs; ES retains
its existing re-preparation behavior. Published or uncertain deliveries are not
replayed to retrofit additional files. A legacy-snapshot migration needs a
separate decision and is not part of this compatibility-preserving correction.

## Early structure enforcement

Both SOAR and ES use the same bounded parser and validated extraction result.
The limits remain 200 MIME nodes including the root and depth 30 with root depth
zero. The parser stops before constructing node 201 or a depth-31 node. The
post-parse defect and transfer-decoding checks remain in place.

The implementation overrides CPython's private `BytesFeedParser._new_message`
hook and uses `_msgstack` solely to enforce depth before allocation. These seams
must be revalidated when adding Python runtimes. No new header-length, content
type, transfer-encoding or RFC-strictness restriction is introduced. A large
single header/body may still require work up to the existing 24-MiB input limit;
this is a tree-complexity bound, not constant-memory parsing.

ES receives the already validated tree and positional attachments from native
intake. Its standalone `build_finding` entry still validates inputs itself.
Neither path changes the outer-body selection or duplicate-header projection.

## Reproducible offline evidence

- `tests/python/test_audit_mime_attachments.py`: appended containers, unchanged old files,
  nested RFC822, ordinary bodies, UTF-8 names, shared attachment limit, and
  old SOAR/ES Vault maps resumed after restart without reuploading old files.
- `tests/python/test_audit_mime_budget.py`: actual node-construction instrumentation,
  chunk-boundary parity, exact limit cases, single ES tree, blocked input
  retaining its slot without publication or automatic reexport.
- `python tools/check_mime_parser_compat.py`: stdlib-only comparison against
  the stock parser on the same runtime. Only unrelated SOAR import dependencies
  are stubbed. This is parser evidence, not native SDK/backend acceptance.

The compatibility probe passed 26 checks each on Python 3.9.25 and 3.13.14.
The Python-3.9 test used a pre-existing local container image with networking
disabled and a read-only checkout; it did not install dependencies.

Two fresh Python-3.13.14 processes measured the same 1,800,067-byte, 50,000-part
synthetic input using `--benchmark baseline` and `--benchmark bounded`:

| Parser | Constructed nodes | Elapsed seconds | Peak RSS, KiB |
|---|---:|---:|---:|
| Stock parser before post-parse rejection | 50,001 | 7.958 | 56,112 |
| Early bounded parser | 200 | 0.036 | 25,764 |

Peak RSS includes interpreter, imports and fixture bytes. These are local sample
measurements, not timing guarantees or production-load results. The invariant
is the number/depth of constructed nodes, not a machine-dependent duration.
