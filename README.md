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


PANDAWATCH X-RAY is a **zero-dependency** trust-geometry and evidence engine.

The core is plain **C11 that uses only the C standard library**. It has its own SHA-256, so there are no external libraries, no package manager and no generated code. The engine stores lifted program IR and security findings in a deterministic, typed form. It serializes them to canonical little-endian bytes and seals them into a single `.pwxray` evidence bundle. A standalone offline verifier then checks every digest in that bundle. Alongside the engine, the repository models trust boundaries formally in Alloy 6 and Agda, analyses reachability and risk in Futhark, and enforces an auth-failure window in POSIX AWK.

## Features

- **Zero dependencies.** The C sources include only `<stdint.h>`, `<stddef.h>`, `<string.h>`, `<stdlib.h>`, `<stdio.h>` and `<inttypes.h>`. CMake links nothing but the project's own static library.
- **Built-in SHA-256.** FIPS 180-4, streaming (`init` / `update` / `final`) or one-shot.
- **Typed IR with fixed layouts.** Every struct has a fixed size, explicit padding fields, and `_Static_assert` size checks.
- **Canonical serialization.**
  - Every field is packed explicitly in little-endian order, and padding is always written as zero.
  - Functions, blocks, successor edges and evidence records are sorted before hashing.
  - Commutative operands are put in a fixed order.
- **Sealed `.pwxray` bundles.** One flat file holds the manifest, evidence records, IR corpus and Alloy model. `manifest_sha256` seals the binary, IR, model and records digests.
- **Offline verifier.** It checks every digest, the canonical encoding, the sort order, the verdict consistency and the record-to-function links. With `--binary`, it also checks the original binary.
- **Three-way verdicts.** Every finding is `PROVEN_COMPLIANT`, `PROVEN_VULNERABLE` or `UNKNOWN`, and an `UNKNOWN` carries an explicit reason code.
- **Formal trust models.** Alloy 6, Agda `--safe --without-K`, Futhark and POSIX AWK.

## Quick start

```sh
git clone https://github.com/AHMADALIPARR/pandawatch.git
cd pandawatch
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build --output-on-failure

./build/pw-xray demo --binary native/tests/proxy.tsv --alloy native/Trust.als -o demo.pwxray
./build/pw-xray-verify demo.pwxray --binary native/tests/proxy.tsv
./build/pw-xray inspect demo.pwxray
```

## CLI usage

### `pw-xray`

```
pw-xray sha256 FILE...                          print SHA-256 digests (sha256sum format)
pw-xray demo --binary FILE --alloy FILE -o OUT  write a bundle from the built-in demo IR and records
pw-xray inspect BUNDLE                          verify, then print manifest, layout and records
```

`demo` builds its bundle from a built-in fixture: two functions, three records, and the binary and Alloy files you pass in.

### `pw-xray-verify`

```
pw-xray-verify BUNDLE [--binary FILE]
```

On success it prints `OK manifest_sha256 <hex>`, followed by the binary, IR corpus, Alloy-model and records digests. On failure it prints `FAIL <reason> (byte offset N)`.

| Exit code | Meaning |
| --- | --- |
| 0 | Bundle verified |
| 1 | Verification failed |
| 2 | Usage or I/O error |

`--binary` also recomputes `binary_size_bytes` and `binary_sha256`.

## C API

Link against the `pandawatch` static library, add `include/pandawatch` to the include path, and include the headers you need.

### `pw_sha256.h`

| Function | Purpose |
| --- | --- |
| `pw_sha256_init`, `pw_sha256_update`, `pw_sha256_final` | Streaming SHA-256 over `pw_sha256_ctx` |
| `pw_sha256(data, len, out[32])` | One-shot digest |
| `pw_hex32(digest, out[65])` | Lowercase hex |

### `pw_xray_ir.h` (Gate 3: typed IR)

| Type | Size | Fields |
| --- | --- | --- |
| `pw_operand_t` | 16 | `kind`, `type`, `_pad0`, `ref_id`, `imm_val` |
| `pw_ir_inst_t` | 64 | `ssa_id`, `opcode`, `out_type`, `flags` (bit 0 crypto const, bit 1 ABI boundary), `source_va`, `src[3]` |
| `pw_ir_block_t` | 32 | `block_id`, `first_inst`, `inst_count`, `succ_count`, `succ_blocks[2]`, `start_va` |
| `pw_ir_func_hdr_t` | 64 | `func_id`, `block_count`, `inst_count`, `stack_frame_bytes`, `entry_va`, `ir_sha256[32]`, `_reserved` |

**Opcodes:**

| Group | Opcodes |
| --- | --- |
| Basic | `NOP 0x00`, `CONST 0x01` |
| Arithmetic and logic | `ADD 0x02`\*, `SUB 0x03`, `MUL 0x04`\*, `XOR 0x05`\*, `AND 0x06`\*, `OR 0x07`\* |
| Shifts and rotates | `SHL 0x08`, `SHR 0x09`, `ROTL 0x0A`, `ROTR 0x0B` |
| Memory | `LOAD 0x10`, `STORE 0x11`, `ALLOCA 0x12` |
| Compare | `CMP_EQ 0x20`, `CMP_LT 0x21` |
| Control flow | `BR 0x30`, `BR_COND 0x31`, `CALL_DIR 0x32`, `CALL_IND 0x33`, `RET 0x34` |
| SSA | `PHI 0x40` |

\* commutative

**Types:** `VOID`, `I1`, `I8`, `I16`, `I32`, `I64`, `V128`, `PTR`.

**Operand kinds:** `NONE`, `SSA`, `IMM`, `BLOCK`, `FUNC`.

**Architectures:** `UNKNOWN`, `X86_64`, `AARCH64`.

### `pw_xray_evidence.h` (Gate 9: evidence)

| Type | Size | Fields |
| --- | --- | --- |
| `pw_evidence_record_t` | 64 | `record_id`, `verdict`, `rule_id`, `unknown_reason`, `detected_bytes`, `required_bytes`, `site_va`, `func_ir_sha256[32]` |
| `pw_evidence_manifest_t` | 192 | see [format](#the-pwxray-format) |

| Enum | Values |
| --- | --- |
| Verdicts | `PROVEN_COMPLIANT 1`, `PROVEN_VULNERABLE 2`, `UNKNOWN 3` |
| Rules | `CLASSICAL_ASYMMETRIC 0x0101`, `FIXED_WIRE_BUFFER 0x0102`, `UNZEROIZED_KEY_STACK 0x0103`, `TRUST_BOUNDARY_CROSS 0x0104`, `HYBRID_PQC_VERIFIED 0x0201` |
| Unknown reasons | `INDIRECT_CALL_TARGET 1`, `DYNAMIC_DLOPEN_SYM 2`, `SELF_MODIFYING_CODE 3`, `STRIPPED_JUMP_TABLE 4`, `STRIPPED_STRIP_LIMIT 5` |

### `pw_xray_canon.h` and `pw_xray_bundle.h`

| Function | Purpose |
| --- | --- |
| `pw_serialize_ir_inst`, `pw_serialize_evidence_record`, `pw_serialize_ir_block`, `pw_serialize_func_hdr`, `pw_serialize_manifest` | Canonical little-endian packing |
| `pw_parse_*` | The matching parsers |
| `pw_sort_records`, `pw_sort_blocks`, `pw_record_cmp` | Canonical ordering |
| `pw_func_ir_digest(f, out)` | Canonical per-function IR digest |
| `pw_derive_overall_verdict(recs, n)` | Overall verdict |
| `pw_bundle_write(in, &out, &out_len)` | Builds a bundle from a `pw_bundle_input_t` (container format, arch, binary, Alloy model, `pw_func_input_t[]`, records) |
| `pw_bundle_verify(bundle, len, binary, binary_len, &report)` | Verifies a bundle and returns a `pw_status_t` and a `pw_verify_report_t` (manifest, region offsets, function count, failing byte offset) |
| `pw_status_str(status)` | Human-readable status |

`pw_derive_overall_verdict` rules:

- `PROVEN_VULNERABLE` if any record is vulnerable.
- Otherwise `UNKNOWN` if any record is unknown or there are no records.
- Otherwise `PROVEN_COMPLIANT`.

### `pw_xray_demo.h` and `pw_io.h`

| Function | Purpose |
| --- | --- |
| `pw_demo_build` | Fills the demo bundle input |
| `pw_read_file`, `pw_write_file` | Whole-file I/O |

## Native trust models (`native/`)

### `Trust.als` (Alloy 6)

The model has these signatures:

- `Principal`, `Device`, `Resource`, `Route` and `Domain`.
- `Session`: subject, device, and the flags `authenticated`, `originBound`, `active` and `revoked`.
- `Request`: session, target, route and `sensitive`.
- `Boundary`, `Transition`, `Artifact` (byte length and capacity), `KeyRelease`, `CredentialFlow` and `CryptoUse`.
- `Snapshot`, ordered with `util/ordering`, which holds the grants, trusted devices, blocked and reverified sessions, admitted requests and the other per-state sets.

`GoodSession` and `CanAdmit` define admission. Two facts constrain every snapshot:

- `Enforcement`: admitted means authorized, protected transitions are authorized, artifacts fit their capacity, PQC-required crypto is not classical-only, key release needs measured boot (and the user factor when required), and approved credential flows send no reusable secret.
- `TemporalRecovery`: a blocked session leaves the blocked set only through reverification.

There are 7 `check` commands: `AdmittedIsAuthorized`, `NoProtectedBypass`, `NoOversizedArtifact`, `NoClassicalOnlyWhenPQCRequired`, `VerifiedUnblock`, `NoReusableSecretOnApprovedFlow` and `KeyReleaseRequiresBoot`. There are 2 `run` commands: `RejectedAttempt` and `ProxyIndependence`. All use `for 5 but 8 Int`.

```sh
java -jar org.alloytools.alloy.dist.jar exec -f -o alloy-out -t text native/Trust.als
```

### `Trust.agda` (Agda, `--safe --without-K`)

The file uses only `Agda.Builtin`.

- The `Facts` record holds six Booleans: `authenticated`, `originBound`, `active`, `revoked`, `deviceTrusted` and `grant`.
- `Admitted f` is built only by `grantAccess`, from six equality proofs.
- `admit : (f : Facts) → Maybe (Admitted f)` decides admission.
- `admitted-authenticated`, `admitted-not-revoked` and `admitted-granted` extract evidence from an admission.
- `authorize` takes a `Transport` (`direct`, `socks` or `onion`). `route-independent` proves that `authorize f p ≡ authorize f q`.

```sh
cd native && agda --safe Trust.agda
```

### `geometry.fut` (Futhark)

| Function | What it does |
| --- | --- |
| `reachable adj seed` | Boolean reachability over an `[n][n]bool` adjacency matrix |
| `protected_reachable adj source protected` | Reachable nodes that are also protected |
| `recursive_risk adj initial` | Propagates the largest reachable `i32` score along edges |
| `entry main` | Runs `reachable` |

```sh
cd native && futhark check geometry.fut
```

### `proxy.awk` (POSIX AWK)

The input is tab-separated with no header:

```
epoch account device route session auth_ok device_ok grant_ok revoked
```

The output is `epoch account session decision reason`.

| Decision | Reason | When |
| --- | --- | --- |
| `DENY` | `INVALID_INPUT` | Malformed row |
| `DENY` | `OUT_OF_ORDER` | Timestamp earlier than the previous row |
| `DENY` | `REVOKED` | Revoked session |
| `DENY` | `AUTH_OR_POLICY_FAILED` | Any flag failed; counted against the account |
| `STEP_UP` | `ACCOUNT_FAILURE_WINDOW` | `limit` failures within `window` seconds |
| `ALLOW` | `VERIFIED` | Otherwise |

`window` defaults to 600 and `limit` to 5.

```sh
cd native
awk -f proxy.awk tests/proxy.tsv | diff -u tests/proxy.expected.tsv -
awk -v window=300 -v limit=3 -f proxy.awk tests/proxy.tsv
```

## The .pwxray format

A bundle is one flat, little-endian file:

| Offset | Size | Contents |
| --- | --- | --- |
| `0` | 192 | `pw_evidence_manifest_t` |
| `192` | `N × 64` | Sorted `pw_evidence_record_t[N]`, where `N = record_count` |
| `records_end` | 16 | IR corpus header: `PW_IR_MAGIC` (`"PWIR"`), `PW_IR_VERSION`, function count, 0 |
| … | per function | `pw_ir_func_hdr_t` (64), then `block_count` blocks (32 each), then `inst_count` instructions (64 each) |
| `ir_end` | to EOF | Raw UTF-8 Alloy model |

Manifest (`PW_EVIDENCE_MAGIC` `"PWEV"`, version `0x00010000`):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | `magic` |
| 4 | 4 | `version` |
| 8 | 1 | `container_format` (1 = ELF64, 2 = PE32+, 3 = Mach-O 64) |
| 9 | 1 | `arch` |
| 10 | 1 | `overall_verdict` |
| 11 | 1 | `_pad0` |
| 12 | 4 | `record_count` |
| 16 | 8 | `binary_size_bytes` |
| 24 | 32 | `binary_sha256` |
| 56 | 32 | `ir_corpus_sha256` (SHA-256 of the whole IR region) |
| 88 | 32 | `alloy_model_sha256` |
| 120 | 32 | `records_sha256` |
| 152 | 8 | `_reserved1` |
| 160 | 32 | `manifest_sha256` (SHA-256 of bytes `[0, 160)`) |

Canonicalization rules:

| Item | Rule |
| --- | --- |
| Functions | Sorted by `entry_va`, then `func_id` |
| Blocks | Sorted by `start_va`, then `block_id`; `succ_blocks` ascending, unused slots zero |
| Records | Sorted by `site_va`, `rule_id`, `verdict`, `unknown_reason` |
| Commutative ops (`ADD`, `MUL`, `XOR`, `AND`, `OR`) | `src[0] ≤ src[1]` by `kind`, `type`, `ref_id`, `imm_val` |
| Instructions | Program order, `ssa_id` strictly ascending |
| Function digest | `ir_sha256` is SHA-256 of the function's serialized blocks and instructions |
| Padding and reserved fields | Always zero |

## Repository layout

```
include/pandawatch/   IR, evidence, SHA-256, bundle and demo headers
src/                  SHA-256, canonical serializers, bundle writer and verifier, demo fixture, file I/O
tools/                pw-xray, pw-xray-verify
tests/                ctest suite and golden digest fixture
native/               Trust.als, Trust.agda, geometry.fut, proxy.awk, tests/*.tsv
ci/                   Alloy result checker (AWK)
docs/                 specification and original native README
.github/workflows/    CI
```

## Build requirements

- **C engine:** a C11 compiler (gcc or clang) and CMake 3.16 or newer. Nothing else is needed.
- **Alloy model:** Alloy 6 (`org.alloytools.alloy.dist.jar`) and Java 21.
- **Agda proofs:** Agda 2.8.
- **Futhark kernels:** Futhark 0.29.
- **Auth-failure window:** any POSIX `awk`.

## License

Dual licensed under the [GNU Affero General Public License v3.0 only](LICENSE-AGPL-3.0) **or** the [SnapKitty Opaque License 1.0](LICENSE-SnapKitty-Opaque-1.0), at your option. See [`LICENSE`](LICENSE).

`SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0`
Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab

The original Gate 3 / Gate 9 specification is in [`docs/source/engine-spec.md`](docs/source/engine-spec.md), and the original native README is in [`docs/pandawatch-native-README.md`](docs/pandawatch-native-README.md).
