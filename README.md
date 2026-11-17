<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
-->

# PANDAWATCH X-RAY: trust geometry and reproducible evidence engine

[![ci](https://github.com/AHMADALIPARR/pandawatch/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/AHMADALIPARR/pandawatch/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-AGPL--3.0%20%2B%20SnapKitty%20Opaque%201.0-blue)](LICENSE)
[![C11](https://img.shields.io/badge/C-C11-00599C?logo=c&logoColor=white)](src/)
[![Alloy 6](https://img.shields.io/badge/Alloy-6.2.0-8A2BE2)](native/Trust.als)
[![Agda](https://img.shields.io/badge/Agda-2.8.0%20safe-5e4fa2)](native/Trust.agda)
[![Futhark](https://img.shields.io/badge/Futhark-0.29.1-5f021f)](native/geometry.fut)
[![AWK](https://img.shields.io/badge/AWK-POSIX-4c1)](native/proxy.awk)
[![no Python](https://img.shields.io/badge/Python-none-lightgrey)](.github/workflows/ci.yml)
[![no JavaScript](https://img.shields.io/badge/JavaScript-none-lightgrey)](.github/workflows/ci.yml)

PANDAWATCH X-RAY is a source-only reference engine for two things:

1. **Trust geometry.** Small formal and executable models of the authorization
   and trust-boundary rules that a session gateway should enforce: Alloy 6
   bounded models, Agda proofs by construction, a Futhark graph-reachability
   kernel and a POSIX AWK rolling failure window.
2. **Reproducible evidence.** A C11 engine for the Gate 3 (deterministic typed
   IR) and Gate 9 (reproducible evidence manifest) specification: fixed-width
   structs with compile-time layout checks, canonical little-endian
   serialization, a self-contained SHA-256, a `.pwxray` bundle writer and a
   standalone offline verifier, `pw-xray-verify`.

It is **not** an exploit tool, an OS penetration predictor, a disassembler or
a production-ready enforcement service. The limits are listed in full in
[Limits](#limits). Nothing in this repository is Python, JavaScript or Metal,
and CI fails if such a file is ever added.

## Contents

- [Repository layout](#repository-layout)
- [Provenance: originals, fixed files, checked copies and new code](#provenance-originals-fixed-files-checked-copies-and-new-code)
- [Building and testing](#building-and-testing)
- [The trust-geometry models (native/)](#the-trust-geometry-models-native)
- [The Gate 3 / Gate 9 engine (C11)](#the-gate-3--gate-9-engine-c11)
- [The .pwxray bundle format](#the-pwxray-bundle-format)
- [The offline verifier](#the-offline-verifier)
- [Measured results](#measured-results)
- [Continuous integration](#continuous-integration)
- [Limits](#limits)
- [License](#license)

## Repository layout

```
native/                     the zip contents, unchanged
  Trust.als                 Alloy 6 bounded model
  Trust.agda                Agda --safe --without-K proofs
  geometry.fut              Futhark reachability and risk propagation
  proxy.awk                 POSIX AWK rolling per-account failure window
  tests/proxy.tsv           deterministic input
  tests/proxy.expected.tsv  oracle output
  tests/proxy.actual.tsv    committed actual output (identical to the oracle)
include/pandawatch/
  pw_xray_ir.h              extracted from the spec, unchanged
  pw_xray_evidence.h        extracted from the spec, plus the _reserved1 fix (compiles)
  pw_xray_evidence_checked.h  earlier checked copy of the same fix (redundant, unused)
  pw_xray_canon.h           prototypes for the spec's serializers
  pw_xray_bundle.h          sorting, packing, writer, verifier API
  pw_sha256.h               SHA-256 API
  pw_xray_demo.h            synthetic fixture API
  pw_io.h                   file helpers
src/
  pw_xray_canon.c           extracted from the spec, unchanged
  pw_xray_canon_checked.c   earlier checked copy (redundant, unused)
  pw_sha256.c               FIPS 180-4 SHA-256
  pw_xray_bundle.c          bundle writer and verifier
  pw_xray_demo.c            synthetic Gate 3 / Gate 9 fixture
  pw_io.c                   whole-file read/write
tools/
  pw_xray_main.c            pw-xray CLI (sha256, demo, inspect)
  pw_xray_verify_main.c     pw-xray-verify
tests/                      ctest programs and the golden digest fixture
ci/alloy-verdicts.awk       parses Alloy CLI output in CI
docs/
  pandawatch-xray-spec.md   the spec prose, with repeated lines collapsed
  pandawatch-native-README.md  the zip README, unchanged
  source/engine-spec.md     the spec markdown, unchanged
.github/workflows/ci.yml
```

## Provenance: originals, fixed files, checked copies and new code

The author's files are kept byte-for-byte, with one exception: the evidence
header, which did not compile as written and has been fixed in place with the
author's approval. The untouched original text of every extracted block is
still in [`docs/source/engine-spec.md`](docs/source/engine-spec.md).

**Byte-for-byte originals (12 files).**

| File | Source |
| --- | --- |
| `native/Trust.als`, `native/Trust.agda`, `native/geometry.fut`, `native/proxy.awk`, `native/tests/proxy.tsv`, `native/tests/proxy.expected.tsv`, `native/tests/proxy.actual.tsv` | `pandawatch-native/` in the zip |
| `docs/pandawatch-native-README.md` | `pandawatch-native/README.md` in the zip |
| `docs/source/engine-spec.md` | the spec markdown |
| `include/pandawatch/pw_xray_ir.h` | spec lines 9-114 (first fenced block) |
| `src/pw_xray_canon.c` | spec lines 202-281 (third fenced block) |
| `LICENSE-AGPL-3.0`, `LICENSE-SnapKitty-Opaque-1.0` | copied from AHMADALIPARR/skytrace |

The originals carry no SPDX header, because adding one would change their
bytes. The license in `LICENSE` covers them.

**Fixed in place (1 file).**

- `include/pandawatch/pw_xray_evidence.h` is spec lines 119-184 plus one
  added line. As written, `pw_evidence_manifest_t` declares
  4 + 4 + 1 + 1 + 1 + 1 + 4 + 8 + 5 x 32 = **184 bytes** of fields, so its
  own `_Static_assert(sizeof(pw_evidence_manifest_t) == 192, ...)` failed with
  both gcc and clang. The spec text also says `manifest_sha256` "hashes the
  first 160 bytes" of the header, but in that layout `manifest_sha256` started
  at offset 152, so bytes 152-159 would have been part of the digest it seals.
  The fix adds one field, `uint64_t _reserved1` (must be 0), after
  `records_sha256`. That places `manifest_sha256` at offset 160 and makes the
  header 192 bytes, so the struct, the assertion and the "first 160 bytes"
  rule now agree. Nothing else changes. The header now compiles as-is, and
  the library builds the spec's own `src/pw_xray_canon.c` against it.

**Checked copies (2 files, now redundant).**
`include/pandawatch/pw_xray_evidence_checked.h` and
`src/pw_xray_canon_checked.c` were added before the in-place fix. They contain
the same `_reserved1` fix (with a renamed include guard and include line).
Nothing builds or includes them any more, and they are kept only because
nothing in this repository is deleted without the author's say-so.

Two ctest cases compile the spec files standalone with
`-std=c11 -Wall -Wextra -Werror -fsyntax-only`. The first,
`evidence_header_compiles_192_bytes`, compiles `pw_xray_evidence.h` through a
probe file that also asserts `sizeof(pw_evidence_manifest_t) == 192`,
`_reserved1` at offset 152 and `manifest_sha256` at offset 160. The second,
`canon_c_compiles`, compiles `src/pw_xray_canon.c`. A third test compiles and
runs against `pw_xray_ir.h`, which was fine as written.

**New files.** Everything else is new and carries this header in its own
comment syntax:

```
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
```

`LICENSE` is the skytrace dual-license notice with its first line changed from
`skytrace` to `pandawatch`.

## Building and testing

Requirements: a C11 compiler (gcc or clang), CMake 3.16 or newer, and a POSIX
`make` or Ninja. There are no other dependencies. SHA-256 is built in.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j1
ctest --test-dir build --output-on-failure
```

All new C code builds with `-std=c11 -Wall -Wextra -Wpedantic -Wshadow
-Wstrict-prototypes -Werror` (`-DPW_WERROR=OFF` turns off `-Werror`).

The trust-geometry checks, which are the verification commands from the
original README:

```sh
cd native
awk -f proxy.awk tests/proxy.tsv > /tmp/pandawatch-proxy.tsv
diff -u tests/proxy.expected.tsv /tmp/pandawatch-proxy.tsv
agda --safe Trust.agda
futhark check geometry.fut
java -jar org.alloytools.alloy.dist.jar exec -f -o alloy-out -t text Trust.als
```

## The trust-geometry models (native/)

These files are the zip contents, unchanged. This section folds in the
original README ([`docs/pandawatch-native-README.md`](docs/pandawatch-native-README.md)).

### Trust.als (Alloy 6)

A bounded relational model with these signatures: principals, devices,
resources, routes and domains, sessions, requests, boundaries, transitions,
artifacts with byte length and capacity, key releases, credential flows and
crypto uses. Each one is observed through an ordered sequence of `Snapshot`s.

- A request may be admitted only from a *good session* that is authenticated,
  origin-bound, active and unrevoked, on a trusted device and not blocked, and
  only for a resource granted to the session's subject.
- A protected transition across a protecting boundary must be authorized.
- A transmitted artifact must fit its capacity.
- A crypto use that requires PQC may not be classical-only.
- A key release needs measured boot, and a user factor when required.
- An approved credential flow may not send a reusable secret.
- A blocked session can become unblocked only through explicit reverification
  (`TemporalRecovery`).

There are 7 `check` commands (`AdmittedIsAuthorized`, `NoProtectedBypass`,
`NoOversizedArtifact`, `NoClassicalOnlyWhenPQCRequired`, `VerifiedUnblock`,
`NoReusableSecretOnApprovedFlow`, `KeyReleaseRequiresBoot`) and 2 `run`
commands (`RejectedAttempt`, `ProxyIndependence`), all at scope `for 5 but 8 Int`.

### Trust.agda (Agda, `--safe --without-K`)

A `Facts` record holds six Booleans: authenticated, origin-bound, active,
revoked, device-trusted and grant. `Admitted f` can only be built from six
equality proofs, so an admission is proof-carrying. `admit` is a decision
procedure that returns `just` an `Admitted f` only when all six facts hold.
Projection lemmas recover authentication, non-revocation and grant from any
admission. `route-independent` proves, by `refl`, that `authorize f p` and
`authorize f q` are equal for any two transports (`direct`, `socks`,
`onion`), because the route is never an input to the decision. The file uses
only `Agda.Builtin` modules, so it needs no standard library.

### geometry.fut (Futhark)

`reachable` computes dense Boolean reachability by iterating a frontier
expansion `n` times over an `n x n` adjacency matrix. `protected_reachable`
masks the result with a protected-node set. `recursive_risk` propagates the
largest reachable non-negative `i32` score along edges, and scores never
decrease. It is a prioritization heuristic, not an exploitability measure.
`main` exposes `reachable`.

### proxy.awk (POSIX AWK)

A rolling per-account failure window over trusted, ordered TSV telemetry with
nine columns: epoch, account, device, route, session, auth_ok, device_ok,
grant_ok and revoked. The output is `ALLOW`, `DENY` or `STEP_UP` with a reason.

- Malformed rows give `INVALID_INPUT` and out-of-order timestamps give
  `OUT_OF_ORDER`.
- A revoked session is denied.
- Any failed flag records a failure for the **account**, not for the source
  route, and is denied.
- Once `limit` failures (default 5) sit inside `window` seconds (default 600),
  the next fully valid request gets `STEP_UP`.
- The route column is read but never grants authority.

The fixture shows this:

- Five failures for `alice` across the `direct`, `socks` and `onion` routes
  are followed by `STEP_UP` at epoch 1005.
- `bob`'s revoked session is denied.
- After the window expires (1605 - 1004 >= 600), `alice` is allowed again.

## The Gate 3 / Gate 9 engine (C11)

The spec ([`docs/pandawatch-xray-spec.md`](docs/pandawatch-xray-spec.md))
defines the structs and two serializers. The new code builds the rest of what
the spec describes.

**Self-contained SHA-256** (`src/pw_sha256.c`). FIPS 180-4, byte-oriented and
endian-independent, with streaming `init/update/final` and a one-shot helper.

**Little-endian packing** (`src/pw_xray_bundle.c`). The spec's
`pw_xray_canon.c` serializes `pw_ir_inst_t` and `pw_evidence_record_t`. The
engine adds field-by-field serializers for `pw_ir_block_t` (32 bytes),
`pw_ir_func_hdr_t` (64 bytes) and the manifest (192 bytes), plus parsers for
all five. Padding and reserved fields are always written as zero, and no
struct is ever written with a raw `fwrite`.

**Canonical sorting.** These are total orders, so the result does not depend
on input order or on `qsort` stability:

- Functions are sorted by `entry_va`, then `func_id`, then their serialized
  bytes.
- Blocks are sorted by `start_va`, then `block_id`, then their bytes.
  `succ_blocks[0..1]` are put in ascending order and unused successor slots
  are zeroed.
- Records are sorted by `(site_va, rule_id, verdict, unknown_reason)`, then
  their serialized bytes.
- Commutative operands (`ADD`, `MUL`, `XOR`, `AND`, `OR`) are ordered by
  `(kind, type, ref_id, imm_val)` inside the spec's own
  `pw_serialize_ir_inst`.

The spec's bullet list says `(kind, ssa_id, imm_val)` for that last order, but
its serialization rules and its code use `(kind, type, ref_id, imm_val)`. The
engine follows the code.

**Per-function digest.** `ir_sha256` is the SHA-256 of the function's sorted
canonical blocks followed by its canonical instructions. Instructions stay in
program order and must have strictly ascending `ssa_id`, because blocks refer
to them by index (`first_inst`).

**Writer** (`pw_bundle_write`). The writer:

- validates the inputs;
- checks that every `UNKNOWN` record has a reason in `0x0001..0x0005` and that
  every other record has reason `0`;
- checks that every non-zero `func_ir_sha256` in a record names a function in
  the same bundle, which is the Gate 3 to Gate 9 link;
- derives `overall_verdict`;
- lays out the bundle and seals the manifest.

The overall verdict is `PROVEN_VULNERABLE` if any record is vulnerable.
Otherwise it is `UNKNOWN` if any record is unknown or if there are no records.
Otherwise it is `PROVEN_COMPLIANT`. An empty run never claims compliance.

**CLI.**

```sh
pw-xray sha256 FILE...                          # like sha256sum
pw-xray demo --binary FILE --alloy FILE -o OUT  # write the synthetic demo bundle
pw-xray inspect BUNDLE                          # verify, then print manifest and records
pw-xray-verify BUNDLE [--binary FILE]           # offline verifier, exit 0/1/2
```

`pw-xray demo` builds its bundle from a **hand-written synthetic fixture**
(`src/pw_xray_demo.c`): two small functions, three records, and whichever
"binary" and Alloy files you pass. Its addresses and findings are made up so
the format can be tested. They describe no real program. The fixture's inputs
are deliberately non-canonical so that sorting and canonicalization run:
functions, blocks, successor pairs, commutative operands and records are all
out of order.

## The .pwxray bundle format

| Range | Contents |
| --- | --- |
| `[0, 192)` | `pw_evidence_manifest_t` (192-byte layout), little-endian |
| `[192, 192 + N*64)` | `N = record_count` sorted `pw_evidence_record_t` |
| `[records_end, ir_end)` | IR corpus |
| `[ir_end, EOF)` | raw UTF-8 Alloy model |

Inside the manifest:

- `binary_sha256` is the SHA-256 of the input binary, and
  `binary_size_bytes` is its length.
- `records_sha256` is the SHA-256 of the record array.
- `ir_corpus_sha256` is the SHA-256 of the whole IR corpus region.
- `alloy_model_sha256` is the SHA-256 of the Alloy text.
- `manifest_sha256` is the SHA-256 of bytes `[0, 160)`, which embed the four
  digests above.

The spec does not say how a reader finds `ir_end`, because the manifest stores
no IR length or function count. The engine therefore starts the IR corpus with
a 16-byte corpus header: `PW_IR_MAGIC` ("PWIR", already defined in
`pw_xray_ir.h`), `PW_IR_VERSION`, `func_count`, and a zero word. That header is
followed, for each function in sorted order, by its `pw_ir_func_hdr_t`, its
`block_count` blocks and its `inst_count` instructions. The corpus header sits
inside the region covered by `ir_corpus_sha256`. This is a design choice of
this repository, not part of the original spec.

## The offline verifier

`pw_bundle_verify` (and the `pw-xray-verify` tool) re-checks a bundle without
the original analysis and without disassembling anything:

1. The length is at least 192, and `manifest_sha256` equals the SHA-256 of
   bytes `[0, 160)`.
2. Magic, version, zero `_pad0` and `_reserved1`, and valid enums.
3. The record region is in bounds and `records_sha256` matches.
4. The IR corpus header is valid. For every function:
   - its reserved field is zero;
   - functions, blocks and successors are in canonical sorted order;
   - every instruction re-serializes to the identical 64 bytes (so operands
     are canonical and padding is zero);
   - `ssa_id` is strictly ascending;
   - block instruction ranges are in bounds;
   - the per-function `ir_sha256` matches.

   Then `ir_corpus_sha256` matches.
5. The rest of the file is the Alloy model: `alloy_model_sha256` matches and
   the text is strict UTF-8.
6. For every record:
   - padding is zero and the enums are valid;
   - `unknown_reason` is consistent with the verdict;
   - records are in canonical order;
   - every non-zero `func_ir_sha256` resolves to a function in the bundle.

   `overall_verdict` must equal the derived verdict.
7. With `--binary FILE`, `binary_size_bytes` and `binary_sha256` are
   recomputed. Without it, the binary digest is covered only by the manifest
   seal.

Exit status is 0 when the bundle verifies, 1 when verification fails (with the
reason and a byte offset), and 2 for usage or I/O errors.

## Measured results

These numbers come from running the tests. They are not estimates. The local
runs used gcc 14.2.0 and clang on Linux x86-64, and CI runs the same suite on
`ubuntu-latest` with both compilers.

- **ctest: 12/12 tests pass** with gcc and with clang.
- **Layout.** 28 `_Static_assert`s on sizes and field offsets of all six
  structs hold, including `offsetof(pw_evidence_manifest_t, manifest_sha256) == 160`.
- **SHA-256.** The NIST vectors pass: the empty string, `abc`, the 448-bit and
  896-bit messages, and one million `a` (fed in 997-byte chunks). Streaming
  output equals one-shot output for every length from 0 to 300 at every split
  point that is a multiple of 7.
- **Canonicalization.** For each of the 5 commutative opcodes and 4 operand
  pairs differing in kind, type, `ref_id` or `imm_val`, both operand orders
  serialize to identical bytes with the smaller operand first. For 7
  non-commutative opcodes, operand order is preserved. Exact little-endian
  bytes are checked for one instruction and one record (65 checks).
- **Sort determinism.** **500/500** shuffled inputs, with functions, blocks,
  successor pairs, commutative operands and records permuted by a fixed-seed
  LCG, produced the identical 1,180-byte bundle.
- **Golden digest.** The demo bundle built from `native/tests/proxy.tsv` (as
  the binary) and `native/Trust.als` (as the Alloy model) is **5,687 bytes**.
  - Bundle SHA-256: `5744443422720edf4fc4e5aba3a31828ebec943f383c81cf8c839bc27113ca8b`
  - `manifest_sha256`: `d922038be57f294a310eba0c4749daf17d91be82a3113619fe2a7c40e6dd4883`

  gcc and clang produce the same bytes, and CI compares them with coreutils
  `sha256sum`.
- **Single-bit mutation.** Flipping each of the **45,496** bits of that bundle
  one at a time was **detected 45,496/45,496** times. The first failing check
  was:

  | First failing check | Bit flips |
  | --- | --- |
  | `alloy_model_sha256` | 36,152 |
  | per-function `ir_sha256` | 4,320 |
  | `manifest_sha256` | 1,536 |
  | `records_sha256` | 1,536 |
  | canonical encoding | 1,026 |
  | sort order | 370 |
  | `ir_corpus_sha256` | 203 |
  | non-zero padding | 191 |
  | truncation | 98 |
  | magic | 32 |
  | version | 32 |
- **Truncation.** All **5,687/5,687** truncated prefixes were rejected, and so
  was appending a byte.
- **Binary mutation.** With `--binary`, all **2,232/2,232** single-bit flips of
  the 279-byte input were rejected (`binary_sha256` mismatch), and so was a
  one-byte-short binary (`binary_size_bytes` mismatch).
- **Speed.** On the build machine (Intel Xeon), the whole `test_bundle`
  program took 1.02 s wall time for about 53,400 in-process verifications of
  bundles up to 5,688 bytes, which is roughly 19 µs each. 100 launches of the
  `pw-xray-verify` process on the demo bundle took 0.083 s in total. That is
  consistent with the spec's "<1 ms" for a bundle of this size. Larger IR
  corpora scale linearly with their byte count.
- **Alloy 6.2.0** (SAT4J, `for 5 but 8 Int`). All 7 `check` commands are
  **UNSAT**, so no counterexample exists within scope. Both `run` commands are
  **SAT**. Running all 9 took about 25 s locally.
- **AWK oracle.** `awk -f proxy.awk tests/proxy.tsv` reproduces
  `tests/proxy.expected.tsv` exactly, and `tests/proxy.actual.tsv` is
  byte-identical to it.

- **Agda 2.8.0** (Ubuntu `agda-bin`, in CI). `agda --safe Trust.agda` type-checks.
- **Futhark 0.29.1** (release tarball, in CI). `futhark check geometry.fut` passes.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request on
`ubuntu-latest`:

| Job | What it does |
| --- | --- |
| `no-python-no-javascript` | Fails on any tracked `.py/.js/.mjs/.cjs/.ts/.tsx/.jsx/.ipynb/.metal`, `package.json`, `requirements.txt` or `pyproject.toml`, or any Python, Node, Deno or Bun shebang |
| `c11 (gcc)`, `c11 (clang)` | CMake build with `-Werror` and the full ctest suite. `pw-xray sha256` must equal `sha256sum` on 7 files, and the demo bundle must equal the committed golden digest before it is verified and inspected |
| `awk-oracle` | The README commands, plus the same oracle under `gawk --posix`, `mawk` and `busybox awk` |
| `agda` | `agda --safe Trust.agda` with the Ubuntu `agda-bin` package |
| `futhark` | `futhark check geometry.fut` with the official 0.29.1 release tarball |
| `alloy` | Runs every command in `Trust.als` with the Alloy 6.2.0 jar on Temurin 21. `ci/alloy-verdicts.awk` requires 9 results: every `check` UNSAT and every `run` SAT |

## Limits

These are the original README's limits, kept and extended.

- **Bounded checks.** Alloy checks are *bounded*. `UNSAT` means there is no
  counterexample within the specified scope (5 atoms per signature, 8-bit
  integers). It does not mean an arbitrary binary or device is secure.
- **Mirrored assertions.** Several Alloy assertions repeat the enforcement
  facts on purpose, so they hold by construction. Production verification has
  to build separate predicates for observed transitions and establish that the
  implementation corresponds to the model. A tautological model is not
  assurance.
- **Agda proves only the abstract model.** Real session revocation, device
  attestation, key secrecy and origin authenticity still need separate
  implementations, threat models and trusted inputs. `Trust.agda` ends with a
  comment about blocked sessions but states no theorem about them.
- **Futhark.** It traverses only the declared edges. Reachability does not
  prove unauthorized reachability. Dense adjacency costs O(n²) memory, and the
  fixed-point loops cost O(n³) work. `recursive_risk` is a heuristic.
- **AWK.** It assumes trusted, sanitized, ordered TSV telemetry and one
  centralized stream. A production gateway needs distributed counters, signed
  telemetry, de-duplication, bounded storage and denial-of-service controls.
  `STEP_UP` asks for more verification. It does not grant access.
- **No binary analysis.** This repository has no loader, disassembler or IR
  lifter. Gates 1-2 and 4-8 of the wider PANDAWATCH X-RAY pipeline are not
  implemented here. The only Gate 3 / Gate 9 data is the synthetic demo
  fixture or data supplied through the C API. No inference here produces
  `PROVEN_VULNERABLE` or `PROVEN_COMPLIANT`, and the engine only records,
  orders and seals verdicts it is given.
- **What the seal does not cover.** The manifest seal detects modification. It
  does not authenticate: anyone can write a new, self-consistent bundle. Signing
  bundles, for example with ML-DSA, is out of scope. Without `--binary`, the
  verifier cannot tell whether `binary_sha256` matches any particular binary.
- **Integer widths.** `detected_bytes` is `uint16_t` in the spec, so observed
  sizes of 65,536 bytes or more cannot be recorded.
- **Format choices.** The IR corpus header and the zeroing of unused
  successor slots are this repository's own choices, documented above. The
  spec does not define them.
- **Alloy and Java.** The Alloy check depends on Java and the Alloy jar from
  GitHub releases. If that download fails, the job fails visibly. It is never
  skipped.

## License

PANDAWATCH is dual licensed under the GNU Affero General Public License
version 3 only ([`LICENSE-AGPL-3.0`](LICENSE-AGPL-3.0)) **or** the SnapKitty
Opaque License 1.0 ([`LICENSE-SnapKitty-Opaque-1.0`](LICENSE-SnapKitty-Opaque-1.0)),
at your option. See [`LICENSE`](LICENSE).

`SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0`
Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
