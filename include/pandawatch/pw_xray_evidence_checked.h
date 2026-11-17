/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 *
 * pw_xray_evidence_checked.h: checked copy of pw_xray_evidence.h (kept byte-for-byte
 * beside this file). The original pw_evidence_manifest_t fields sum to 184 bytes,
 * so its _Static_assert(sizeof == 192) fails to compile. This copy adds one
 * uint64_t _reserved1 (must be 0) after records_sha256 so manifest_sha256 sits at
 * offset 160 and the header is 192 bytes, matching the spec text "manifest_sha256
 * hashes the first 160 bytes". Include guard renamed. Nothing else changed.
 */
#ifndef PW_XRAY_EVIDENCE_CHECKED_H
#define PW_XRAY_EVIDENCE_CHECKED_H

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
    uint64_t _reserved1;             /* Must be 0 (checked fix: places manifest_sha256 at offset 160) */
    uint8_t  manifest_sha256[32];    /* SHA-256 of bytes [0..159] of this header */
} pw_evidence_manifest_t;
_Static_assert(sizeof(pw_evidence_manifest_t) == 192, "pw_evidence_manifest_t must be 192 bytes");

#endif /* PW_XRAY_EVIDENCE_CHECKED_H */

