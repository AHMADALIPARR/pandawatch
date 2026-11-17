<!--
SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
-->

# PANDAWATCH X-RAY: Gate 3 and Gate 9 specification (prose)

This is the prose of [`docs/source/engine-spec.md`](source/engine-spec.md) with
the copy-paste repeats collapsed to one copy each. The three code blocks were
extracted byte-for-byte to the files linked below; the source markdown is kept
unchanged in `docs/source/`.

To make **Gate 3 (Deterministic Typed IR)** and **Gate 9 (Reproducible Evidence Manifest)** bit-for-bit deterministic across x86-64 and AArch64 hosts without padding leaks, pointer serialization, or non-deterministic ordering, every struct must use fixed-width `<stdint.h>` types, explicit _Static_assert layout verification, zero uninitialized padding bytes, and canonical little-endian wire serialization.  
Below is the standalone C11 specification (pw_xray_ir.h and pw_xray_canon.c) engineered for zero-dependency execution and direct SHA-256 hashing.  

## 1. Gate 3: Deterministic, Typed Intermediate Representation (pw_xray_ir.h)

To guarantee identical IR digests across runs and architectures:  
* **No raw pointers in IR nodes:** All references use dense, contiguous uint32_t arena indices (ssa_id, block_id, func_id).  
* **Canonical operand ordering:** Commutative operations (PW_OP_ADD, PW_OP_XOR, PW_OP_AND, PW_OP_OR, PW_OP_MUL) normalize operands so src0 <= src1 by (kind, ssa_id, imm_val).  
* **Zero implicit struct padding:** Every struct is explicitly padded to 8-byte boundaries and verified at compile time with _Static_assert.  

Code: [`include/pandawatch/pw_xray_ir.h`](../include/pandawatch/pw_xray_ir.h) (lines 9-114 of the source markdown).

## 2. Gate 9: Reproducible Evidence Manifest & Explicit UNKNOWN Schema (pw_xray_evidence.h)

Gate 9 forbids probabilistic guessing. Every finding is strictly partitioned into PROVEN_VULNERABLE, PROVEN_COMPLIANT, or UNKNOWN with an exact pw_unknown_reason_t code and instruction virtual address.  

Code: [`include/pandawatch/pw_xray_evidence.h`](../include/pandawatch/pw_xray_evidence.h) (lines 119-184 of the source markdown).

## 3. Canonical Wire Serialization Rules (pw_xray_canon.c)

To ensure **bit-for-bit reproducibility** regardless of host endianness, memory allocator addresses, or hash-table iteration order, the serializer enforces four strict invariants before computing any SHA-256 hash:  
1. **Deterministic Sorting Before Serialization:**  
    * Functions (pw_ir_func_hdr_t) are sorted ascending by entry_va.  
    * Basic blocks (pw_ir_block_t) are sorted ascending by start_va, and succ_blocks[0..1] are sorted ascending.  
    * Evidence records (pw_evidence_record_t) are sorted ascending by (site_va, rule_id, verdict, unknown_reason).  
2. **Commutative Operand Canonicalization:**  
    * Before hashing an instruction, if opcode is commutative (ADD, MUL, XOR, AND, OR), src[0] and src[1] are ordered deterministically by comparing (kind, type, ref_id, imm_val).  
3. **Explicit Little-Endian Byte Packing (No Direct Struct fwrite):**  
    * Even though x86-64 and AArch64 are both little-endian, serializing field-by-field into an explicit `uint8_t *buf` eliminates any possibility of compiler-inserted padding or strict-aliasing UB.  
4. **Self-Verifying Manifest Seal:**  
    * manifest_sha256 hashes the first 160 bytes of the serialized pw_evidence_manifest_t (which itself embeds binary_sha256, ir_corpus_sha256, alloy_model_sha256, and records_sha256). Any single-bit mutation in the input binary, recovered IR, Alloy model, or UNKNOWN classification invalidates the root manifest digest.  

Code: [`src/pw_xray_canon.c`](../src/pw_xray_canon.c) (lines 202-281 of the source markdown).

## Canonical File Layout on Disk (.pwxray Bundle)

When pw-xray finishes a run, it emits a single flat binary evidence file (`<binary>.pwxray`) structured sequentially as:  
1. [0x0000 .. 0x00BF] — pw_evidence_manifest_t (192 bytes)  
2. [0x00C0 .. 0x00C0 + N*64) — Sorted pw_evidence_record_t[N] array  
3. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
4. [ir_end .. EOF) — Raw UTF-8 Alloy .als trust-boundary model (alloy_model_sha256)  

Any auditor (or CI acceptance harness) can verify the entire run offline in <1 ms using a standalone C11 verifier that checks the 4 constituent SHA-256 digests against manifest_sha256 without re-disassembling the target binary.  
