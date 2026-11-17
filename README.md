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


PANDAWATCH X-RAY models trust boundaries (who may act, from which session and device, across which boundary) and records analysis results as reproducible, tamper-evident evidence. This repository has two parts. The first is a C11 engine that turns a typed IR and its findings into a deterministic `.pwxray` bundle sealed with a SHA-256 manifest, plus an offline verifier that rechecks every digest. The second is a set of trust-geometry models: an Alloy 6 trust model, Agda proofs, Futhark reachability and risk propagation, and a POSIX AWK auth-failure window.

## Features

- **Deterministic IR and evidence.** Fixed-width structs with no implicit padding, checked at compile time with `_Static_assert`. They are written as explicit little-endian bytes and never with a raw struct `fwrite`.
- **Canonical ordering.** Functions, blocks, successor edges, commutative operands and evidence records are sorted before hashing, so the same input always gives the same bytes on any compiler or host.
- **Self-contained SHA-256** (FIPS 180-4) with no external dependencies.
- **Sealed bundles.** The manifest embeds the binary, IR, Alloy-model and records digests, and `manifest_sha256` seals the header. A single flipped bit anywhere in a bundle fails verification.
- **Offline verifier.** `pw-xray-verify` checks digests, canonical form, sort order, verdict consistency and links from each record to its function, without re-analysing the binary.
- **Explicit UNKNOWN.** Every finding is `PROVEN_COMPLIANT`, `PROVEN_VULNERABLE` or `UNKNOWN` with a reason code, and an empty run is never reported as compliant.
- **Formal trust models** in Alloy 6, Agda (`--safe --without-K`), Futhark and POSIX AWK, all checked in CI.
- **No Python, no JavaScript.** CI rejects either.

## Quick start

```sh
git clone https://github.com/AHMADALIPARR/pandawatch.git
cd pandawatch
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build --output-on-failure

# Build the demo bundle and verify it offline
./build/pw-xray demo --binary native/tests/proxy.tsv --alloy native/Trust.als -o demo.pwxray
./build/pw-xray-verify demo.pwxray --binary native/tests/proxy.tsv
./build/pw-xray inspect demo.pwxray
```

`pw-xray-verify` prints `OK` and each digest, or `FAIL <reason> (byte offset N)`. It exits with 0 if the bundle verifies, 1 if verification fails, and 2 on a usage or I/O error.

## Components

### C11 evidence engine (`include/pandawatch/`, `src/`, `tools/`)

| Command | Purpose |
| --- | --- |
| `pw-xray demo --binary FILE --alloy FILE -o OUT` | Writes a bundle from the built-in synthetic Gate 3 / Gate 9 fixture |
| `pw-xray inspect BUNDLE` | Verifies a bundle, then prints its manifest, layout and records |
| `pw-xray sha256 FILE...` | Prints SHA-256 digests in `sha256sum` format |
| `pw-xray-verify BUNDLE [--binary FILE]` | Standalone offline verifier. `--binary` also recomputes `binary_sha256` and `binary_size_bytes` |

The library API is in `pw_xray_bundle.h`:

- `pw_bundle_write` builds a bundle from functions, blocks, instructions and records.
- `pw_bundle_verify` checks one.
- `pw_func_ir_digest` gives a function's canonical Gate 3 digest.
- The structs are defined in `pw_xray_ir.h` and `pw_xray_evidence.h`.

### Trust.als (Alloy 6)

A relational model of sessions, requests, devices, boundaries, transitions, artifacts, key releases, credential flows and crypto use across ordered snapshots. It states and checks these properties:

- An admitted request comes from an authenticated, origin-bound, active, unrevoked session on a trusted device, with a grant for the resource.
- A protected transition is authorized.
- An artifact fits its capacity.
- A use that requires PQC is not classical-only.
- A key release needs measured boot.
- An approved credential flow sends no reusable secret.
- A blocked session can be unblocked only through reverification.

It has 7 `check` commands and 2 `run` commands.

```sh
java -jar org.alloytools.alloy.dist.jar exec -f -o alloy-out -t text native/Trust.als
```

### Trust.agda (Agda)

Admission is proof-carrying: an `Admitted f` value can only be built from proofs that all six facts hold (authenticated, origin-bound, active, not revoked, trusted device, grant). `admit` decides admission. `route-independent` proves that the transport (`direct`, `socks`, `onion`) never changes the decision.

```sh
cd native && agda --safe Trust.agda
```

### geometry.fut (Futhark)

These functions work on a dense adjacency matrix:

- `reachable` gives Boolean reachability from a seed set.
- `protected_reachable` restricts that to protected nodes.
- `recursive_risk` propagates the largest reachable non-negative risk score along edges.

`main` is the entry point for `reachable`.

```sh
cd native && futhark check geometry.fut
```

### proxy.awk (POSIX AWK)

A rolling per-account auth-failure window over 9-column TSV telemetry: epoch, account, device, route, session, auth_ok, device_ok, grant_ok, revoked. It prints `ALLOW`, `DENY` or `STEP_UP` with a reason.

- Failures are counted per account, not per route.
- `limit` (default 5) failures within `window` seconds (default 600) trigger `STEP_UP`.
- Revoked sessions, malformed rows and out-of-order rows are denied.

```sh
cd native
awk -f proxy.awk tests/proxy.tsv | diff -u tests/proxy.expected.tsv -
awk -v window=300 -v limit=3 -f proxy.awk tests/proxy.tsv
```

## The .pwxray bundle format

A bundle is one flat little-endian file:

| Offset | Size | Contents |
| --- | --- | --- |
| `0` | 192 | `pw_evidence_manifest_t` |
| `192` | `N × 64` | `N = record_count` evidence records, sorted |
| `192 + N×64` | 16 | IR corpus header: `"PWIR"` magic, IR version, function count, 0 |
| … | per function | `pw_ir_func_hdr_t` (64), then its blocks (32 each), then its instructions (64 each) |
| `ir_end` | to EOF | Raw UTF-8 Alloy model |

The manifest:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 16 | magic `"PWEV"`, version, container format, arch, overall verdict, pad, record count |
| 16 | 8 | `binary_size_bytes` |
| 24 | 32 | `binary_sha256` |
| 56 | 32 | `ir_corpus_sha256` (whole IR region) |
| 88 | 32 | `alloy_model_sha256` |
| 120 | 32 | `records_sha256` |
| 152 | 8 | reserved, 0 |
| 160 | 32 | `manifest_sha256` = SHA-256 of bytes `[0, 160)` |

Canonicalization rules:

- Functions are sorted by `entry_va`, blocks by `start_va`, and records by `(site_va, rule_id, verdict, unknown_reason)`.
- Successors are put in ascending order and unused successor slots are zeroed.
- `ADD`, `MUL`, `XOR`, `AND` and `OR` order their operands by `(kind, type, ref_id, imm_val)`.
- Padding and reserved fields are always zero.
- A function's `ir_sha256` covers its serialized blocks and instructions.
- The overall verdict is `PROVEN_VULNERABLE` if any record is vulnerable. Otherwise it is `UNKNOWN` if any record is unknown or there are no records. Otherwise it is `PROVEN_COMPLIANT`.

## Repository layout

```
include/pandawatch/   IR and evidence structs, engine API
src/                  SHA-256, canonical serializers, bundle writer/verifier
tools/                pw-xray and pw-xray-verify
tests/                ctest suite and golden digest fixture
native/               Trust.als, Trust.agda, geometry.fut, proxy.awk, AWK fixtures
ci/                   Alloy result checker
docs/                 spec prose; original spec and native README in docs/source and docs/
.github/workflows/    CI
```

## Requirements

| Tool | Version used in CI |
| --- | --- |
| C compiler | gcc and clang on `ubuntu-latest`, `-std=c11 -Wall -Wextra -Wpedantic -Werror` |
| CMake | 3.16 or newer |
| Alloy | 6.2.0 jar on Temurin Java 21 |
| Agda | 2.8.0 (Ubuntu `agda-bin`) |
| Futhark | 0.29.1 |
| AWK | any POSIX awk (tested with mawk, gawk `--posix` and busybox) |

The C engine has no dependencies beyond the C standard library.

## Limitations

- Alloy results hold within the declared scope `for 5 but 8 Int` (`native/Trust.als` lines 155-163).
- The 7 Alloy checks restate the `Enforcement` and `TemporalRecovery` facts (`native/Trust.als` lines 91-110), so they pass because of those facts.
- The closing comment on blocked sessions in `native/Trust.agda` (lines 61-62) has no theorem behind it.
- `geometry.fut` uses O(n²) memory and O(n³) work on dense adjacency matrices.
- There is no loader, disassembler or IR lifter. Bundles come from the demo fixture or from data passed to `pw_bundle_write`.
- Bundles are sealed but not signed.
- `detected_bytes` is `uint16_t`, so it cannot record sizes of 65,536 bytes or more.

## License

Dual licensed under the [GNU Affero General Public License v3.0 only](LICENSE-AGPL-3.0) **or** the [SnapKitty Opaque License 1.0](LICENSE-SnapKitty-Opaque-1.0), at your option; see [`LICENSE`](LICENSE).

`SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0`
Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab

The original Gate 3 / Gate 9 specification is in [`docs/source/engine-spec.md`](docs/source/engine-spec.md) (prose: [`docs/pandawatch-xray-spec.md`](docs/pandawatch-xray-spec.md)), and the original native README is in [`docs/pandawatch-native-README.md`](docs/pandawatch-native-README.md).
