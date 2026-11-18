<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
-->

# PANDAWATCH X-RAY: trust geometry and reproducible evidence engine

[![ci](https://github.com/AHMADALIPARR/pandawatch/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/AHMADALIPARR/pandawatch/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-AGPL--3.0%20%2B%20SnapKitty%20Opaque%201.0-blue)](LICENSE)
[![C11](https://img.shields.io/badge/C-C11-00599C?logo=c&logoColor=white)](src/)
[![C23](https://img.shields.io/badge/C-C23-00599C?logo=c&logoColor=white)](xasm/)
[![FORTRAN 77](https://img.shields.io/badge/FORTRAN-77-734f96?logo=fortran&logoColor=white)](fortran/pw_struct.f)
[![x86-64 asm](https://img.shields.io/badge/asm-x86--64%20GNU%20as-6e4c13)](asm/pw_x86_decode.S)
[![Alloy 6](https://img.shields.io/badge/Alloy-6.2.0-8A2BE2)](native/Trust.als)
[![Agda](https://img.shields.io/badge/Agda-2.8.0%20safe-5e4fa2)](native/Trust.agda)
[![Futhark](https://img.shields.io/badge/Futhark-0.29.1-5f021f)](native/geometry.fut)
[![AWK](https://img.shields.io/badge/AWK-POSIX-4c1)](native/proxy.awk)
[![no Python](https://img.shields.io/badge/Python-none-lightgrey)](.github/workflows/ci.yml)
[![no JavaScript](https://img.shields.io/badge/JavaScript-none-lightgrey)](.github/workflows/ci.yml)


PANDAWATCH X-RAY is a **zero-dependency** trust-geometry and evidence engine.

The core is plain **C11 that uses only the C standard library**. It has its own SHA-256, so there are no external libraries, no package manager and no generated code. The engine stores lifted program IR and security findings in a deterministic, typed form. It serializes them to canonical little-endian bytes and seals them into a single `.pwxray` evidence bundle. A standalone offline verifier then checks every digest in that bundle. Alongside the engine, the repository models trust boundaries formally in Alloy 6 and Agda, analyses reachability and risk in Futhark, and enforces an auth-failure window in POSIX AWK.

## Features

- **Zero dependencies.** The C sources include only `<stdint.h>`, `<stddef.h>`, `<string.h>`, `<stdlib.h>`, `<stdio.h>` and `<inttypes.h>`, plus `<ctype.h>` and `<stdarg.h>` in `pw-xasm` and `<math.h>` in its test. CMake links nothing but the project's own static libraries, plus libgfortran (and libm for the `pw-xasm` test).
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
- **pw-xasm.** An x86-64 decoder in GNU assembler, a FORTRAN 77 parser for the `.pwxray` structs, and a C23 assembler, disassembler and lifter. It links only libc and libgfortran.

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

## `pw-xasm`: x86-64 assembler, disassembler and FORTRAN 77 struct parser

`pw-xasm` combines three parts, each in its own language:

- An x86-64 instruction decoder written in GNU assembler (`asm/pw_x86_decode.S`).
- A struct parser for the `.pwxray` wire layout, written in FORTRAN 77 (`fortran/pw_struct.f`).
- A C23 driver (`xasm/`) that adds an assembler for the same instruction subset, Intel-syntax output, and a lifter from raw code to a `.pwxray` bundle.

It links against libc and libgfortran and nothing else. It builds when CMake finds a Fortran compiler on an x86-64 host.

### Usage

```
pw-xasm asm <in.s> -o <out.bin> [--base ADDR]
pw-xasm disasm <in.bin> [--base ADDR] [--listing]
pw-xasm lift <in.bin> -o <out.pwxray> [--base ADDR] [--alloy model.als]
pw-xasm structs <bundle.pwxray> [--ir]
pw-xasm layout
```

- **`asm`** assembles Intel-syntax text into a flat binary.
  - Input is one instruction per line, with `label:` definitions and `;` or `#` comments.
  - `--base` sets the load address; the default is `0x401000`.
- **`disasm`** prints one instruction per line, followed by `; address: bytes`. `asm` reads this output back in and produces the same bytes. `--listing` prints `offset mnemonic` pairs instead.
- **`lift`** decodes a code blob into one `pw_ir` function and writes a `.pwxray` bundle with `pw_bundle_write`. The bundle verifies with `pw-xray-verify --binary <in.bin>`. See [How `lift` builds the bundle](#how-lift-builds-the-bundle).
- **`structs`** decodes a `.pwxray` file through the Fortran routines and prints:
  - the file size and its Adler-32;
  - the manifest and every evidence record and function header, field by field;
  - record statistics.

  It checks that every padding and reserved field in the file is zero. `--ir` also prints every block and instruction. The exit status is 1 if any padding byte is nonzero.
- **`layout`** prints the Fortran layout table: every field's offset, size and padding flag, for all six structs.

### Supported instruction subset (x86-64)

| Encoding | Instructions |
| --- | --- |
| `90`, `C3`, `CC` | `nop`, `ret`, `int3` |
| `50+r`, `58+r` | `push r64`, `pop r64` |
| `B8+r` | `mov r32, imm32`; with REX.W: `movabs r64, imm64` |
| `01 03`, `09 0B`, `21 23`, `29 2B`, `31 33`, `39 3B` | `add`, `or`, `and`, `sub`, `xor`, `cmp`: r/m,reg and reg,r/m |
| `85` | `test r/m, reg` |
| `89`, `8B` | `mov r/m, reg` and `mov reg, r/m` |
| `8D` | `lea reg, [mem]` |
| `83 /0,1,4,5,6,7` | `add or and sub xor cmp r/m, imm8` |
| `81 /0,1,4,5,6,7` | `add or and sub xor cmp r/m, imm32` |
| `C7 /0` | `mov r/m, imm32` |
| `FF /2`, `FF /4` | `call r/m64`, `jmp r/m64` |
| `E8`, `E9`, `EB` | `call rel32`, `jmp rel32`, `jmp short rel8` |
| `70`–`7F`, `0F 80`–`0F 8F` | `jo jno jb jae je jne jbe ja js jns jp jnp jl jge jle jg`, with rel8 (`short`) or rel32 |

**Operands**

- Registers: `rax`–`r15` and `eax`–`r15d`. The operand size comes from REX.W.
- Memory: `[base + index*scale + disp]`, `[index*scale + disp]`, `[disp32]` and `[rip + disp32]`, with an optional `qword ptr` or `dword ptr`.

**Decoding**

- The decoder handles REX prefixes, ModRM, SIB, and disp8/disp32 displacements. It rejects anything outside the subset, any instruction longer than 15 bytes, and truncated input.
- Branch targets print as absolute addresses. `short` selects the rel8 form.

**Encoding**

The assembler picks the encoding GNU as uses for the same text:

- For reg,reg it uses the r/m,reg opcode.
- It uses `83` when the immediate fits in 8 bits.
- It picks the shortest displacement, adding a SIB byte for `rsp`/`r12` bases and a zero disp8 for `rbp`/`r13`.
- `mov r64, imm` uses `C7 /0`, or `movabs` if the value does not fit in a sign-extended imm32.

### How `lift` builds the bundle

**IR mapping**

| x86-64 | `PW_OP_*` |
| --- | --- |
| `add`, `lea`, register-to-register `mov` | `ADD` |
| `sub` / `xor` / `and` / `or` | `SUB` / `XOR` / `AND` / `OR` |
| `cmp`, `test` | `CMP_EQ` |
| `mov reg, imm`, `movabs` | `CONST` |
| `mov reg, [mem]`, `pop` | `LOAD` |
| `mov [mem], reg`, `mov [mem], imm`, `push` | `STORE` |
| `call rel32` / `call r/m` | `CALL_DIR` / `CALL_IND` |
| `jmp` / `jcc` | `BR` / `BR_COND` |
| `ret` | `RET` |
| `nop`, `int3` | `NOP` |

**Operands**

- Register operands are SSA operands whose `ref_id` is the register number (0–15).
- Memory operands become the base register plus an immediate displacement.
- Branch operands name the target block.

**Blocks**

- Blocks start at the entry, at every in-blob branch target, and after every `jmp`, `jcc` and `ret`.
- Successor edges are sorted.

**Evidence records**

- Every `call r/m` produces an `UNKNOWN` record (`INDIRECT_CALL_TARGET`), and every `jmp r/m` produces one with `STRIPPED_JUMP_TABLE`. Both use rule `TRUST_BOUNDARY_CROSS`, and each record is linked to the function digest.
- The manifest records `arch = X86_64` and `container_format = 1`.

### FORTRAN 77 struct parser (`fortran/pw_struct.f`)

The parser is fixed-form FORTRAN 77, built with `gfortran -std=legacy`. Every routine is a plain external, and the C prototypes are in `xasm/pw_fortran.h`.

**Calling from C:** use the lower-case name plus `_`. Every argument is passed by reference: `INTEGER` → `int32_t *`, `INTEGER*8` → `int64_t *`, `INTEGER*1` → `uint8_t *`, `DOUBLE PRECISION` → `double *`. A `CHARACTER*(*)` argument adds a hidden `size_t` length after the other arguments.

`KIND` selects the struct:

| `KIND` | Struct | Size |
| --- | --- | --- |
| 1 | `pw_operand_t` | 16 |
| 2 | `pw_ir_inst_t` | 64 |
| 3 | `pw_ir_block_t` | 32 |
| 4 | `pw_ir_func_hdr_t` | 64 |
| 5 | `pw_evidence_record_t` | 64 |
| 6 | `pw_evidence_manifest_t` | 192 |

`IERR` is 0 on success, 1 for a bad `KIND`, 2 for a short buffer and 3 for a bad field index.

| Routine | Purpose |
| --- | --- |
| `PWLAYT(KIND, I, IOFF, ISIZ, IPAD, IERR)` | Layout table entry for field `I`: offset, size, and whether it is padding. With `I = 0` it returns the field count and the struct size. |
| `PWFNAM(KIND, I, NAME)` | C field name of field `I`. |
| `PWGETN(B, IOFF, N)` / `PWPUTN(B, IOFF, N, V)` | Read or write an `N`-byte little-endian integer. |
| `PWDEC(KIND, B, NB, VALS, NV, IERR)` | Decode a struct into `INTEGER*8` values in field order. 32-byte digests come out as four 64-bit lanes. |
| `PWENC(KIND, VALS, B, NB, IERR)` | Encode values back into bytes. Padding is always written as zero. |
| `PWVAL(KIND, B, NB, IBAD, IERR)` | Index of the first nonzero padding or reserved field, or 0. |
| `PWADL(B, N)` | Adler-32 checksum. |
| `PWRST(B, NREC, ISTAT, DSTAT)` | Statistics over packed evidence records (below). |

`PWRST` reports:

- counts per verdict and per unknown reason;
- the number of invalid verdicts and the number of records with nonzero padding;
- the mean, population variance, minimum and maximum of `detected_bytes` and `required_bytes` (Welford);
- how many records have `required_bytes > detected_bytes`, and the total shortfall.

### Tests

- **`xasm_encodings_roundtrip_fortran_lift`:**
  - known encodings, byte for byte;
  - assemble → disassemble → reassemble over `tests/xasm/corpus.s`;
  - 200,000 random byte strings, where every decodable one must give the same text after format → assemble → decode → format;
  - Fortran layout against `offsetof` / `sizeof`;
  - `PWDEC`/`PWENC` round trip on every struct in a demo bundle, plus `PWVAL` on corrupted padding;
  - Adler-32, and `PWRST` against a C reference;
  - lift → `pw_bundle_verify`.
- **`xasm_cli_roundtrip_lift_verify`:** the same round trip and lift through the CLI and `pw-xray-verify`.
- **`xasm_objdump_crosscheck`:** GNU `objdump -d` must agree with the decoder on every instruction offset and mnemonic in the corpus.
- **`xasm_fortran_layout`** and **`xasm_fortran_structs_demo_bundle`:** run `pw-xasm layout` and `pw-xasm structs` on the demo bundle.

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
xasm/                 pw-xasm (C23): assembler, Intel-syntax formatter, lifter, CLI
asm/                  x86-64 decoder (GNU assembler)
fortran/              FORTRAN 77 struct parser
tests/                ctest suite and golden digest fixture
tests/xasm/           pw-xasm tests, instruction corpus, objdump cross-check
native/               Trust.als, Trust.agda, geometry.fut, proxy.awk, tests/*.tsv
ci/                   Alloy result checker (AWK)
docs/                 specification and original native README
.github/workflows/    CI
```

## Build requirements

- **C engine:** a C11 compiler (gcc or clang) and CMake 3.16 or newer. Nothing else is needed.
- **pw-xasm:** an x86-64 host, a C23 compiler (gcc or clang), gfortran, and CMake 3.21 or newer. The objdump cross-check needs GNU binutils.
- **Alloy model:** Alloy 6 (`org.alloytools.alloy.dist.jar`) and Java 21.
- **Agda proofs:** Agda 2.8.
- **Futhark kernels:** Futhark 0.29.
- **Auth-failure window:** any POSIX `awk`.

## License

Dual licensed under the [GNU Affero General Public License v3.0 only](LICENSE-AGPL-3.0) **or** the [SnapKitty Opaque License 1.0](LICENSE-SnapKitty-Opaque-1.0), at your option. See [`LICENSE`](LICENSE).

`SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0`
Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab

The original Gate 3 / Gate 9 specification is in [`docs/source/engine-spec.md`](docs/source/engine-spec.md), and the original native README is in [`docs/pandawatch-native-README.md`](docs/pandawatch-native-README.md).
