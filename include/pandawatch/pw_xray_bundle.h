/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Gate 3 / Gate 9 engine: canonical sorting, little-endian packing of the
 * remaining structs, the .pwxray bundle writer, and the offline verifier. */
#ifndef PW_XRAY_BUNDLE_H
#define PW_XRAY_BUNDLE_H

#include <stddef.h>
#include <stdint.h>
#include "pw_xray_ir.h"
#include "pw_xray_evidence.h"

#define PW_MANIFEST_BYTES       192u
#define PW_MANIFEST_SEALED_BYTES 160u
#define PW_RECORD_BYTES          64u
#define PW_INST_BYTES            64u
#define PW_BLOCK_BYTES           32u
#define PW_FUNC_HDR_BYTES        64u
#define PW_IR_CORPUS_HDR_BYTES   16u

/* One lifted function handed to the writer. The writer never mutates it. */
typedef struct {
    pw_ir_func_hdr_t     hdr;      /* block_count/inst_count/ir_sha256 are recomputed */
    const pw_ir_block_t *blocks;
    uint32_t             block_count;
    const pw_ir_inst_t  *insts;
    uint32_t             inst_count;
} pw_func_input_t;

typedef struct {
    uint8_t  container_format;     /* 1=ELF64, 2=PE32+, 3=Mach-O 64 */
    uint8_t  arch;                 /* pw_arch_t */
    const uint8_t *binary;         /* Gate 1 input fixture bytes */
    size_t   binary_len;
    const uint8_t *alloy_model;    /* raw UTF-8 .als text */
    size_t   alloy_len;
    const pw_func_input_t *funcs;
    uint32_t func_count;
    const pw_evidence_record_t *records;
    uint32_t record_count;
} pw_bundle_input_t;

typedef enum {
    PW_OK = 0,
    PW_E_NOMEM,
    PW_E_ARG,
    PW_E_TRUNCATED,
    PW_E_MAGIC,
    PW_E_VERSION,
    PW_E_NONZERO_PAD,
    PW_E_BAD_ENUM,
    PW_E_MANIFEST_DIGEST,
    PW_E_RECORDS_DIGEST,
    PW_E_IR_DIGEST,
    PW_E_FUNC_DIGEST,
    PW_E_ALLOY_DIGEST,
    PW_E_BINARY_DIGEST,
    PW_E_BINARY_SIZE,
    PW_E_NOT_CANONICAL,
    PW_E_NOT_SORTED,
    PW_E_VERDICT,
    PW_E_UNKNOWN_REASON,
    PW_E_DANGLING_FUNC_REF,
    PW_E_UTF8,
    PW_E_COUNT
} pw_status_t;

const char *pw_status_str(pw_status_t s);

/* Little-endian packing of the structs pw_xray_canon.c does not cover. */
void pw_serialize_ir_block(const pw_ir_block_t *b, uint8_t out[32]);
void pw_serialize_func_hdr(const pw_ir_func_hdr_t *f, uint8_t out[64]);
void pw_serialize_manifest(const pw_evidence_manifest_t *m, uint8_t out[192]);

/* Parsers (inverse of the serializers; no validation beyond byte order). */
void pw_parse_ir_inst(const uint8_t in[64], pw_ir_inst_t *out);
void pw_parse_ir_block(const uint8_t in[32], pw_ir_block_t *out);
void pw_parse_func_hdr(const uint8_t in[64], pw_ir_func_hdr_t *out);
void pw_parse_evidence_record(const uint8_t in[64], pw_evidence_record_t *out);
void pw_parse_manifest(const uint8_t in[192], pw_evidence_manifest_t *out);

/* Canonical sorting (total orders; ties broken on serialized bytes). */
void pw_sort_records(pw_evidence_record_t *recs, size_t n);
void pw_sort_blocks(pw_ir_block_t *blocks, size_t n);   /* also sorts succ_blocks */
/* Canonical Gate 3 digest of one function: SHA-256 over its sorted,
 * canonical blocks followed by its instructions (program order, ssa_id
 * strictly ascending). Returns PW_OK or a validation error. */
int  pw_func_ir_digest(const pw_func_input_t *f, uint8_t out[32]);
int  pw_record_cmp(const pw_evidence_record_t *a, const pw_evidence_record_t *b);

/* Overall verdict: any PROVEN_VULNERABLE wins; else any UNKNOWN (or no
 * records at all) gives UNKNOWN; else PROVEN_COMPLIANT. */
uint8_t pw_derive_overall_verdict(const pw_evidence_record_t *recs, size_t n);

/* Writes a complete .pwxray bundle into a malloc'd buffer (*out, *out_len). */
pw_status_t pw_bundle_write(const pw_bundle_input_t *in, uint8_t **out, size_t *out_len);

typedef struct {
    pw_evidence_manifest_t manifest;
    size_t   records_off, records_end;
    size_t   ir_off, ir_end;
    size_t   alloy_off;
    uint32_t func_count;
    size_t   fail_offset;          /* byte offset related to the failure, if any */
} pw_verify_report_t;

/* Offline verifier. binary may be NULL (then binary_sha256 is only covered by
 * the manifest seal and is not recomputed). */
pw_status_t pw_bundle_verify(const uint8_t *bundle, size_t len,
                             const uint8_t *binary, size_t binary_len,
                             pw_verify_report_t *report);

#endif /* PW_XRAY_BUNDLE_H */
