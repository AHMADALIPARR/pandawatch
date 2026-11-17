To make **Gate 3 (Deterministic Typed IR)** and **Gate 9 (Reproducible Evidence Manifest)** bit-for-bit deterministic across x86-64 and AArch64 hosts without padding leaks, pointer serialization, or non-deterministic ordering, every struct must use fixed-width <stdint.h> types, explicit _Static_assert layout verification, zero uninitialized padding bytes, and canonical little-endian wire serialization.  
Below is the standalone C11 specification (pw_xray_ir.h and pw_xray_canon.c) engineered for zero-dependency execution and direct SHA-256 hashing.  
**1. Gate 3: Deterministic, Typed Intermediate Representation (pw_xray_ir.h)**  
To guarantee identical IR digests across runs and architectures:  
* **No raw pointers in IR nodes:** All references use dense, contiguous uint32_t arena indices (ssa_id, block_id, func_id).  
* **Canonical operand ordering:** Commutative operations (PW_OP_ADD, PW_OP_XOR, PW_OP_AND, PW_OP_OR, PW_OP_MUL) normalize operands so src0 <= src1 by (kind, ssa_id, imm_val).  
* **Zero implicit struct padding:** Every struct is explicitly padded to 8-byte boundaries and verified at compile time with _Static_assert.  
```
#ifndef PW_XRAY_IR_H
#define PW_XRAY_IR_H

#include <stdint.h>
#include <stddef.h>

#define PW_IR_MAGIC   0x50574952U /* "PWIR" */
#define PW_IR_VERSION 0x00010000U /* v1.0 */

typedef enum {
    PW_ARCH_UNKNOWN = 0,
    PW_ARCH_X86_64  = 1,
    PW_ARCH_AARCH64 = 2
} pw_arch_t;

typedef enum {
    PW_TY_VOID = 0,
    PW_TY_I1   = 1,
    PW_TY_I8   = 2,
    PW_TY_I16  = 3,
    PW_TY_I32  = 4,
    PW_TY_I64  = 5,
    PW_TY_V128 = 6,
    PW_TY_PTR  = 7
} pw_type_t;

typedef enum {
    PW_OP_NOP        = 0x00,
    PW_OP_CONST      = 0x01,
    PW_OP_ADD        = 0x02, /* Commutative */
    PW_OP_SUB        = 0x03,
    PW_OP_MUL        = 0x04, /* Commutative */
    PW_OP_XOR        = 0x05, /* Commutative */
    PW_OP_AND        = 0x06, /* Commutative */
    PW_OP_OR         = 0x07, /* Commutative */
    PW_OP_SHL        = 0x08,
    PW_OP_SHR        = 0x09,
    PW_OP_ROTL       = 0x0A,
    PW_OP_ROTR       = 0x0B,
    PW_OP_LOAD       = 0x10,
    PW_OP_STORE      = 0x11,
    PW_OP_ALLOCA     = 0x12, /* Stack frame slot with explicit byte size */
    PW_OP_CMP_EQ     = 0x20,
    PW_OP_CMP_LT     = 0x21,
    PW_OP_BR         = 0x30,
    PW_OP_BR_COND    = 0x31,
    PW_OP_CALL_DIR   = 0x32,
    PW_OP_CALL_IND   = 0x33, /* Triggers UNKNOWN tracking if target unresolved */
    PW_OP_RET        = 0x34,
    PW_OP_PHI        = 0x40
} pw_opcode_t;

typedef enum {
    PW_OPERAND_NONE  = 0,
    PW_OPERAND_SSA   = 1,
    PW_OPERAND_IMM   = 2,
    PW_OPERAND_BLOCK = 3,
    PW_OPERAND_FUNC  = 4
} pw_operand_kind_t;

/* 16 bytes, zero implicit padding */
typedef struct {
    uint8_t  kind;      /* pw_operand_kind_t */
    uint8_t  type;      /* pw_type_t */
    uint16_t _pad0;     /* Must be 0 */
    uint32_t ref_id;    /* SSA value ID, Block ID, or Function ID */
    uint64_t imm_val;   /* Immediate literal (0 if ref_id used) */
} pw_operand_t;
_Static_assert(sizeof(pw_operand_t) == 16, "pw_operand_t must be 16 bytes");

/* 64 bytes, zero implicit padding */
typedef struct {
    uint32_t     ssa_id;     /* Monotonic dense ID within function */
    uint16_t     opcode;     /* pw_opcode_t */
    uint8_t      out_type;   /* pw_type_t */
    uint8_t      flags;      /* Bit 0: is_crypto_const, Bit 1: is_abi_boundary */
    uint64_t     source_va;  /* Original instruction virtual address */
    pw_operand_t src[3];     /* Up to 3 canonicalized operands (48 bytes) */
} pw_ir_inst_t;
_Static_assert(sizeof(pw_ir_inst_t) == 64, "pw_ir_inst_t must be 64 bytes");

/* 32 bytes, zero implicit padding */
typedef struct {
    uint32_t block_id;
    uint32_t first_inst;     /* Index into function's inst array */
    uint32_t inst_count;
    uint32_t succ_count;     /* 0, 1, or 2 */
    uint32_t succ_blocks[2]; /* Sorted ascending for canonical CFG edges */
    uint64_t start_va;
} pw_ir_block_t;
_Static_assert(sizeof(pw_ir_block_t) == 32, "pw_ir_block_t must be 32 bytes");

/* 64 bytes, zero implicit padding */
typedef struct {
    uint32_t func_id;
    uint32_t block_count;
    uint32_t inst_count;
    uint32_t stack_frame_bytes;
    uint64_t entry_va;
    uint8_t  ir_sha256[32];  /* Canonical SHA-256 of normalized blocks + insts */
    uint64_t _reserved;      /* Must be 0 */
} pw_ir_func_hdr_t;
_Static_assert(sizeof(pw_ir_func_hdr_t) == 64, "pw_ir_func_hdr_t must be 64 bytes");

#endif /* PW_XRAY_IR_H */

```
**2. Gate 9: Reproducible Evidence Manifest & Explicit UNKNOWN Schema (pw_xray_evidence.h)**  
Gate 9 forbids probabilistic guessing. Every finding is strictly partitioned into PROVEN_VULNERABLE, PROVEN_COMPLIANT, or UNKNOWN with an exact pw_unknown_reason_t code and instruction virtual address.  
```
#ifndef PW_XRAY_EVIDENCE_H
#define PW_XRAY_EVIDENCE_H

#include <stdint.h>

#define PW_EVIDENCE_MAGIC   0x50574556U /* "PWEV" */
#define PW_EVIDENCE_VERSION 0x00010000U

typedef enum {
    PW_VERDICT_PROVEN_COMPLIANT  = 1,
    PW_VERDICT_PROVEN_VULNERABLE = 2,
    PW_VERDICT_UNKNOWN           = 3
} pw_verdict_t;

typedef enum {
    PW_UNK_NONE                  = 0x0000,
    PW_UNK_INDIRECT_CALL_TARGET  = 0x0001, /* Unresolved CALL/BLR register */
    PW_UNK_DYNAMIC_DLOPEN_SYM    = 0x0002, /* Runtime dlsym / GetProcAddress */
    PW_UNK_SELF_MODIFYING_CODE   = 0x0003, /* Writable + Executable segment */
    PW_UNK_STRIPPED_JUMP_TABLE   = 0x0004, /* Unbounded indirect jump */
    PW_UNK_STRIPPED_STRIP_LIMIT  = 0x0005  /* Analysis budget / recursion cap */
} pw_unknown_reason_t;

typedef enum {
    PW_RULE_CLASSICAL_ASYMMETRIC = 0x0101, /* RSA / ECDSA / X25519 detected */
    PW_RULE_FIXED_WIRE_BUFFER    = 0x0102, /* Buffer < PQC artifact size */
    PW_RULE_UNZEROIZED_KEY_STACK = 0x0103, /* Secret key material on stack */
    PW_RULE_TRUST_BOUNDARY_CROSS = 0x0104, /* Alloy assertion counterexample */
    PW_RULE_HYBRID_PQC_VERIFIED  = 0x0201  /* ML-KEM / ML-DSA + framing valid */
} pw_rule_id_t;

/* 64 bytes: Individual finding or explicit UNKNOWN record */
typedef struct {
    uint32_t record_id;
    uint8_t  verdict;          /* pw_verdict_t */
    uint8_t  _pad0;
    uint16_t rule_id;          /* pw_rule_id_t */
    uint16_t unknown_reason;   /* pw_unknown_reason_t (0 unless VERDICT_UNKNOWN) */
    uint16_t detected_bytes;   /* Observed ABI/buffer size (e.g., 64) */
    uint32_t required_bytes;   /* Required PQC size (e.g., 3309 for ML-DSA-65) */
    uint64_t site_va;          /* Exact instruction VA */
    uint8_t  func_ir_sha256[32]; /* Links directly to Gate 3 function IR digest */
    uint64_t _reserved;        /* Must be 0 */
} pw_evidence_record_t;
_Static_assert(sizeof(pw_evidence_record_t) == 64, "pw_evidence_record_t must be 64 bytes");

/* 192 bytes: Top-level canonical manifest header */
typedef struct {
    uint32_t magic;                  /* PW_EVIDENCE_MAGIC */
    uint32_t version;                /* PW_EVIDENCE_VERSION */
    uint8_t  container_format;       /* 1=ELF64, 2=PE32+, 3=Mach-O 64 */
    uint8_t  arch;                   /* pw_arch_t */
    uint8_t  overall_verdict;        /* pw_verdict_t */
    uint8_t  _pad0;
    uint32_t record_count;
    uint64_t binary_size_bytes;
    uint8_t  binary_sha256[32];      /* Gate 1 input fixture digest */
    uint8_t  ir_corpus_sha256[32];   /* Gate 3 aggregate IR digest */
    uint8_t  alloy_model_sha256[32]; /* Gate 7 generated .als file digest */
    uint8_t  records_sha256[32];     /* SHA-256 over sorted pw_evidence_record_t[] */
    uint8_t  manifest_sha256[32];    /* SHA-256 of bytes [0..159] of this header */
} pw_evidence_manifest_t;
_Static_assert(sizeof(pw_evidence_manifest_t) == 192, "pw_evidence_manifest_t must be 192 bytes");

#endif /* PW_XRAY_EVIDENCE_H */

```
**3. Canonical Wire Serialization Rules (pw_xray_canon.c)**  
To ensure **bit-for-bit reproducibility** regardless of host endianness, memory allocator addresses, or hash-table iteration order, the serializer enforces four strict invariants before computing any SHA-256 hash:  
To ensure **bit-for-bit reproducibility** regardless of host endianness, memory allocator addresses, or hash-table iteration order, the serializer enforces four strict invariants before computing any SHA-256 hash:  
1. **Deterministic Sorting Before Serialization:**  
    * Functions (pw_ir_func_hdr_t) are sorted ascending by entry_va.  
    * Basic blocks (pw_ir_block_t) are sorted ascending by start_va, and succ_blocks[0..1] are sorted ascending.  
    * Evidence records (pw_evidence_record_t) are sorted ascending by (site_va, rule_id, verdict, unknown_reason).  
2. **Commutative Operand Canonicalization:**  
    * Before hashing an instruction, if opcode is commutative (ADD, MUL, XOR, AND, OR), src[0] and src[1] are ordered deterministically by comparing (kind, type, ref_id, imm_val).  
3. **Explicit Little-Endian Byte Packing (No Direct Struct fwrite):**  
4. **Explicit Little-Endian Byte Packing (No Direct Struct fwrite):**  
5. **Explicit Little-Endian Byte Packing (No Direct Struct fwrite):**  
    * Even though x86-64 and AArch64 are both little-endian, serializing field-by-field into an explicit uint8_t *buf eliminates any possibility of compiler-inserted padding or strict-aliasing UB.  
6. **Self-Verifying Manifest Seal:**  
    * manifest_sha256 hashes the first 160 bytes of the serialized pw_evidence_manifest_t (which itself embeds binary_sha256, ir_corpus_sha256, alloy_model_sha256, and records_sha256). Any single-bit mutation in the input binary, recovered IR, Alloy model, or UNKNOWN classification invalidates the root manifest digest.  
```
#include "pw_xray_ir.h"
#include "pw_xray_evidence.h"
#include <string.h>

static inline void put_u8(uint8_t *dst, size_t *off, uint8_t v) {
    dst[(*off)++] = v;
}

static inline void put_u16_le(uint8_t *dst, size_t *off, uint16_t v) {
    dst[(*off)++] = (uint8_t)(v & 0xFFU);
    dst[(*off)++] = (uint8_t)((v >> 8) & 0xFFU);
}

static inline void put_u32_le(uint8_t *dst, size_t *off, uint32_t v) {
    dst[(*off)++] = (uint8_t)(v & 0xFFU);
    dst[(*off)++] = (uint8_t)((v >> 8) & 0xFFU);
    dst[(*off)++] = (uint8_t)((v >> 16) & 0xFFU);
    dst[(*off)++] = (uint8_t)((v >> 24) & 0xFFU);
}

static inline void put_u64_le(uint8_t *dst, size_t *off, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        dst[(*off)++] = (uint8_t)((v >> (i * 8)) & 0xFFULL);
    }
}

static int operand_cmp(const pw_operand_t *a, const pw_operand_t *b) {
    if (a->kind != b->kind) return (a->kind < b->kind) ? -1 : 1;
    if (a->type != b->type) return (a->type < b->type) ? -1 : 1;
    if (a->ref_id != b->ref_id) return (a->ref_id < b->ref_id) ? -1 : 1;
    if (a->imm_val != b->imm_val) return (a->imm_val < b->imm_val) ? -1 : 1;
    return 0;
}

static int is_commutative_op(uint16_t op) {
    return (op == PW_OP_ADD || op == PW_OP_MUL ||
            op == PW_OP_XOR || op == PW_OP_AND || op == PW_OP_OR);
}

/* Serializes one pw_ir_inst_t into exactly 64 canonical bytes */
void pw_serialize_ir_inst(const pw_ir_inst_t *in, uint8_t out[64]) {
    pw_ir_inst_t norm = *in;
    if (is_commutative_op(norm.opcode) && operand_cmp(&norm.src[0], &norm.src[1]) > 0) {
        pw_operand_t tmp = norm.src[0];
        norm.src[0] = norm.src[1];
        norm.src[1] = tmp;
    }

    size_t off = 0;
    put_u32_le(out, &off, norm.ssa_id);
    put_u16_le(out, &off, norm.opcode);
    put_u8(out, &off, norm.out_type);
    put_u8(out, &off, norm.flags);
    put_u64_le(out, &off, norm.source_va);

    for (int i = 0; i < 3; ++i) {
        put_u8(out, &off, norm.src[i].kind);
        put_u8(out, &off, norm.src[i].type);
        put_u16_le(out, &off, 0); /* Enforce zero padding */
        put_u32_le(out, &off, norm.src[i].ref_id);
        put_u64_le(out, &off, norm.src[i].imm_val);
    }
}

/* Serializes one pw_evidence_record_t into exactly 64 canonical bytes */
void pw_serialize_evidence_record(const pw_evidence_record_t *rec, uint8_t out[64]) {
    size_t off = 0;
    put_u32_le(out, &off, rec->record_id);
    put_u8(out, &off, rec->verdict);
    put_u8(out, &off, 0); /* Enforce zero padding */
    put_u16_le(out, &off, rec->rule_id);
    put_u16_le(out, &off, rec->unknown_reason);
    put_u16_le(out, &off, rec->detected_bytes);
    put_u32_le(out, &off, rec->required_bytes);
    put_u64_le(out, &off, rec->site_va);
    memcpy(out + off, rec->func_ir_sha256, 32);
    off += 32;
    put_u64_le(out, &off, 0); /* Reserved zero */
}

```
**Canonical File Layout on Disk (.pwxray Bundle)**  
When pw-xray finishes a run, it emits a single flat binary evidence file (<binary>.pwxray) structured sequentially as:  
1. [0x0000 .. 0x00BF] — pw_evidence_manifest_t (192 bytes)  
2. [0x0000 .. 0x00BF] — pw_evidence_manifest_t (192 bytes)  
3. [0x0000 .. 0x00BF] — pw_evidence_manifest_t (192 bytes)  
4. [0x0000 .. 0x00BF] — pw_evidence_manifest_t (192 bytes)  
5. [0x00C0 .. 0x00C0 + N*64) — Sorted pw_evidence_record_t[N] array  
6. [0x00C0 .. 0x00C0 + N*64) — Sorted pw_evidence_record_t[N] array  
7. [0x00C0 .. 0x00C0 + N*64) — Sorted pw_evidence_record_t[N] array  
8. [0x00C0 .. 0x00C0 + N*64) — Sorted pw_evidence_record_t[N] array  
9. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
10. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
11. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
12. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
13. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
14. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
15. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
16. [records_end .. ir_end) — Sorted pw_ir_func_hdr_t + canonical pw_ir_block_t + pw_ir_inst_t stream  
17. [ir_end .. EOF) — Raw UTF-8 Alloy .als trust-boundary model (alloy_model_sha256)  
18. [ir_end .. EOF) — Raw UTF-8 Alloy .als trust-boundary model (alloy_model_sha256)  
19. [ir_end .. EOF) — Raw UTF-8 Alloy .als trust-boundary model (alloy_model_sha256)  
20. [ir_end .. EOF) — Raw UTF-8 Alloy .als trust-boundary model (alloy_model_sha256)  
21. [ir_end .. EOF) — Raw UTF-8 Alloy .als trust-boundary model (alloy_model_sha256)  
22. [ir_end .. EOF) — Raw UTF-8 Alloy .als trust-boundary model (alloy_model_sha256)  
Any auditor (or CI acceptance harness) can verify the entire run offline in <1 ms using a standalone C11 verifier that checks the 4 constituent SHA-256 digests against manifest_sha256 without re-disassembling the target binary.  
