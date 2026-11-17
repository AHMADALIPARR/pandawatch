/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* .pwxray bundle engine: little-endian packing for the structs the spec's
 * pw_xray_canon.c leaves out, canonical sorting, the bundle writer and the
 * standalone offline verifier.
 *
 * Bundle layout (offsets in bytes):
 *   [0, 192)                     pw_evidence_manifest_t (checked layout)
 *   [192, 192 + N*64)            sorted pw_evidence_record_t[N]
 *   [records_end, ir_end)        IR corpus: 16-byte corpus header
 *                                (PW_IR_MAGIC, PW_IR_VERSION, func_count, 0)
 *                                then per function, sorted by entry_va:
 *                                pw_ir_func_hdr_t, its sorted blocks, its insts
 *   [ir_end, EOF)                raw UTF-8 Alloy model
 */
#include "pw_xray_bundle.h"
#include "pw_xray_canon.h"
#include "pw_sha256.h"

#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- bytes -- */

static void wr32(uint8_t *p, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8u * i));
}
static void wr64(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8u * i));
}
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    uint32_t v = 0;
    for (unsigned i = 0; i < 4; ++i) v |= (uint32_t)p[i] << (8u * i);
    return v;
}
static uint64_t rd64(const uint8_t *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8u * i);
    return v;
}

static int is_zero32(const uint8_t d[32]) {
    uint8_t acc = 0;
    for (unsigned i = 0; i < 32; ++i) acc |= d[i];
    return acc == 0;
}

/* ------------------------------------------------------------ serialize -- */

void pw_serialize_ir_block(const pw_ir_block_t *b, uint8_t out[32]) {
    wr32(out + 0, b->block_id);
    wr32(out + 4, b->first_inst);
    wr32(out + 8, b->inst_count);
    wr32(out + 12, b->succ_count);
    wr32(out + 16, b->succ_blocks[0]);
    wr32(out + 20, b->succ_blocks[1]);
    wr64(out + 24, b->start_va);
}

void pw_serialize_func_hdr(const pw_ir_func_hdr_t *f, uint8_t out[64]) {
    wr32(out + 0, f->func_id);
    wr32(out + 4, f->block_count);
    wr32(out + 8, f->inst_count);
    wr32(out + 12, f->stack_frame_bytes);
    wr64(out + 16, f->entry_va);
    memcpy(out + 24, f->ir_sha256, 32);
    wr64(out + 56, 0); /* _reserved: always serialized as zero */
}

void pw_serialize_manifest(const pw_evidence_manifest_t *m, uint8_t out[192]) {
    wr32(out + 0, m->magic);
    wr32(out + 4, m->version);
    out[8] = m->container_format;
    out[9] = m->arch;
    out[10] = m->overall_verdict;
    out[11] = 0; /* _pad0 */
    wr32(out + 12, m->record_count);
    wr64(out + 16, m->binary_size_bytes);
    memcpy(out + 24, m->binary_sha256, 32);
    memcpy(out + 56, m->ir_corpus_sha256, 32);
    memcpy(out + 88, m->alloy_model_sha256, 32);
    memcpy(out + 120, m->records_sha256, 32);
    wr64(out + 152, 0); /* _reserved1 */
    memcpy(out + 160, m->manifest_sha256, 32);
}

/* ---------------------------------------------------------------- parse -- */

static void parse_operand(const uint8_t *p, pw_operand_t *o) {
    o->kind = p[0];
    o->type = p[1];
    o->_pad0 = rd16(p + 2);
    o->ref_id = rd32(p + 4);
    o->imm_val = rd64(p + 8);
}

void pw_parse_ir_inst(const uint8_t in[64], pw_ir_inst_t *out) {
    out->ssa_id = rd32(in + 0);
    out->opcode = rd16(in + 4);
    out->out_type = in[6];
    out->flags = in[7];
    out->source_va = rd64(in + 8);
    for (unsigned i = 0; i < 3; ++i) parse_operand(in + 16 + 16 * i, &out->src[i]);
}

void pw_parse_ir_block(const uint8_t in[32], pw_ir_block_t *out) {
    out->block_id = rd32(in + 0);
    out->first_inst = rd32(in + 4);
    out->inst_count = rd32(in + 8);
    out->succ_count = rd32(in + 12);
    out->succ_blocks[0] = rd32(in + 16);
    out->succ_blocks[1] = rd32(in + 20);
    out->start_va = rd64(in + 24);
}

void pw_parse_func_hdr(const uint8_t in[64], pw_ir_func_hdr_t *out) {
    out->func_id = rd32(in + 0);
    out->block_count = rd32(in + 4);
    out->inst_count = rd32(in + 8);
    out->stack_frame_bytes = rd32(in + 12);
    out->entry_va = rd64(in + 16);
    memcpy(out->ir_sha256, in + 24, 32);
    out->_reserved = rd64(in + 56);
}

void pw_parse_evidence_record(const uint8_t in[64], pw_evidence_record_t *out) {
    out->record_id = rd32(in + 0);
    out->verdict = in[4];
    out->_pad0 = in[5];
    out->rule_id = rd16(in + 6);
    out->unknown_reason = rd16(in + 8);
    out->detected_bytes = rd16(in + 10);
    out->required_bytes = rd32(in + 12);
    out->site_va = rd64(in + 16);
    memcpy(out->func_ir_sha256, in + 24, 32);
    out->_reserved = rd64(in + 56);
}

void pw_parse_manifest(const uint8_t in[192], pw_evidence_manifest_t *out) {
    out->magic = rd32(in + 0);
    out->version = rd32(in + 4);
    out->container_format = in[8];
    out->arch = in[9];
    out->overall_verdict = in[10];
    out->_pad0 = in[11];
    out->record_count = rd32(in + 12);
    out->binary_size_bytes = rd64(in + 16);
    memcpy(out->binary_sha256, in + 24, 32);
    memcpy(out->ir_corpus_sha256, in + 56, 32);
    memcpy(out->alloy_model_sha256, in + 88, 32);
    memcpy(out->records_sha256, in + 120, 32);
    out->_reserved1 = rd64(in + 152);
    memcpy(out->manifest_sha256, in + 160, 32);
}

/* ------------------------------------------------------------- validate -- */

static int verdict_ok(uint8_t v) {
    return v == PW_VERDICT_PROVEN_COMPLIANT || v == PW_VERDICT_PROVEN_VULNERABLE ||
           v == PW_VERDICT_UNKNOWN;
}

static int rule_ok(uint16_t r) {
    return r == PW_RULE_CLASSICAL_ASYMMETRIC || r == PW_RULE_FIXED_WIRE_BUFFER ||
           r == PW_RULE_UNZEROIZED_KEY_STACK || r == PW_RULE_TRUST_BOUNDARY_CROSS ||
           r == PW_RULE_HYBRID_PQC_VERIFIED;
}

static pw_status_t record_semantics(const pw_evidence_record_t *r) {
    if (!verdict_ok(r->verdict) || !rule_ok(r->rule_id)) return PW_E_BAD_ENUM;
    if (r->verdict == PW_VERDICT_UNKNOWN) {
        if (r->unknown_reason < PW_UNK_INDIRECT_CALL_TARGET ||
            r->unknown_reason > PW_UNK_STRIPPED_STRIP_LIMIT) return PW_E_UNKNOWN_REASON;
    } else if (r->unknown_reason != PW_UNK_NONE) {
        return PW_E_UNKNOWN_REASON;
    }
    return PW_OK;
}

/* Strict UTF-8 (no overlongs, no surrogates, max U+10FFFF). */
static int utf8_ok(const uint8_t *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        if (c < 0x80u) { ++i; continue; }
        size_t len;
        uint32_t cp;
        if (c >= 0xC2u && c <= 0xDFu) { len = 2; cp = c & 0x1Fu; }
        else if (c >= 0xE0u && c <= 0xEFu) { len = 3; cp = c & 0x0Fu; }
        else if (c >= 0xF0u && c <= 0xF4u) { len = 4; cp = c & 0x07u; }
        else return 0;
        if (n - i < len) return 0;
        for (size_t k = 1; k < len; ++k) {
            if ((s[i + k] & 0xC0u) != 0x80u) return 0;
            cp = (cp << 6) | (s[i + k] & 0x3Fu);
        }
        if ((len == 3 && cp < 0x800u) || (len == 4 && cp < 0x10000u) ||
            cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) return 0;
        i += len;
    }
    return 1;
}

/* ------------------------------------------------------------------ sort -- */

int pw_record_cmp(const pw_evidence_record_t *a, const pw_evidence_record_t *b) {
    if (a->site_va != b->site_va) return a->site_va < b->site_va ? -1 : 1;
    if (a->rule_id != b->rule_id) return a->rule_id < b->rule_id ? -1 : 1;
    if (a->verdict != b->verdict) return a->verdict < b->verdict ? -1 : 1;
    if (a->unknown_reason != b->unknown_reason) return a->unknown_reason < b->unknown_reason ? -1 : 1;
    uint8_t sa[64], sb[64];
    pw_serialize_evidence_record(a, sa);
    pw_serialize_evidence_record(b, sb);
    int c = memcmp(sa, sb, 64);
    return (c > 0) - (c < 0);
}

static int qs_record(const void *a, const void *b) {
    return pw_record_cmp((const pw_evidence_record_t *)a, (const pw_evidence_record_t *)b);
}

void pw_sort_records(pw_evidence_record_t *recs, size_t n) {
    if (n > 1) qsort(recs, n, sizeof *recs, qs_record);
}

static void canon_block(pw_ir_block_t *b) {
    if (b->succ_count == 2 && b->succ_blocks[0] > b->succ_blocks[1]) {
        uint32_t t = b->succ_blocks[0];
        b->succ_blocks[0] = b->succ_blocks[1];
        b->succ_blocks[1] = t;
    }
    if (b->succ_count < 2) b->succ_blocks[1] = 0;
    if (b->succ_count < 1) b->succ_blocks[0] = 0;
}

static int block_cmp(const pw_ir_block_t *a, const pw_ir_block_t *b) {
    if (a->start_va != b->start_va) return a->start_va < b->start_va ? -1 : 1;
    if (a->block_id != b->block_id) return a->block_id < b->block_id ? -1 : 1;
    uint8_t sa[32], sb[32];
    pw_serialize_ir_block(a, sa);
    pw_serialize_ir_block(b, sb);
    int c = memcmp(sa, sb, 32);
    return (c > 0) - (c < 0);
}

static int qs_block(const void *a, const void *b) {
    return block_cmp((const pw_ir_block_t *)a, (const pw_ir_block_t *)b);
}

void pw_sort_blocks(pw_ir_block_t *blocks, size_t n) {
    for (size_t i = 0; i < n; ++i) canon_block(&blocks[i]);
    if (n > 1) qsort(blocks, n, sizeof *blocks, qs_block);
}

static int func_cmp(const pw_ir_func_hdr_t *a, const pw_ir_func_hdr_t *b) {
    if (a->entry_va != b->entry_va) return a->entry_va < b->entry_va ? -1 : 1;
    if (a->func_id != b->func_id) return a->func_id < b->func_id ? -1 : 1;
    uint8_t sa[64], sb[64];
    pw_serialize_func_hdr(a, sa);
    pw_serialize_func_hdr(b, sb);
    int c = memcmp(sa, sb, 64);
    return (c > 0) - (c < 0);
}

uint8_t pw_derive_overall_verdict(const pw_evidence_record_t *recs, size_t n) {
    int any_unknown = (n == 0);
    for (size_t i = 0; i < n; ++i) {
        if (recs[i].verdict == PW_VERDICT_PROVEN_VULNERABLE) return PW_VERDICT_PROVEN_VULNERABLE;
        if (recs[i].verdict == PW_VERDICT_UNKNOWN) any_unknown = 1;
    }
    return any_unknown ? PW_VERDICT_UNKNOWN : PW_VERDICT_PROVEN_COMPLIANT;
}

/* --------------------------------------------------------- func digest -- */

static pw_status_t check_func_shape(const pw_ir_block_t *blocks, uint32_t nb,
                                    const pw_ir_inst_t *insts, uint32_t ni) {
    for (uint32_t i = 0; i < nb; ++i) {
        if (blocks[i].succ_count > 2) return PW_E_NOT_CANONICAL;
        if ((uint64_t)blocks[i].first_inst + blocks[i].inst_count > ni) return PW_E_NOT_CANONICAL;
    }
    for (uint32_t i = 1; i < ni; ++i) {
        if (insts[i].ssa_id <= insts[i - 1].ssa_id) return PW_E_NOT_SORTED;
    }
    return PW_OK;
}

/* Digest over already-canonical blocks plus instructions. */
static void digest_blocks_insts(const pw_ir_block_t *blocks, uint32_t nb,
                                const pw_ir_inst_t *insts, uint32_t ni, uint8_t out[32]) {
    pw_sha256_ctx ctx;
    uint8_t buf[64];
    pw_sha256_init(&ctx);
    for (uint32_t i = 0; i < nb; ++i) {
        pw_serialize_ir_block(&blocks[i], buf);
        pw_sha256_update(&ctx, buf, 32);
    }
    for (uint32_t i = 0; i < ni; ++i) {
        pw_serialize_ir_inst(&insts[i], buf);
        pw_sha256_update(&ctx, buf, 64);
    }
    pw_sha256_final(&ctx, out);
}

static pw_ir_block_t *sorted_blocks_copy(const pw_func_input_t *f) {
    size_t n = f->block_count ? f->block_count : 1;
    pw_ir_block_t *b = (pw_ir_block_t *)malloc(n * sizeof *b);
    if (!b) return NULL;
    if (f->block_count) memcpy(b, f->blocks, f->block_count * sizeof *b);
    pw_sort_blocks(b, f->block_count);
    return b;
}

int pw_func_ir_digest(const pw_func_input_t *f, uint8_t out[32]) {
    if (!f || (f->block_count && !f->blocks) || (f->inst_count && !f->insts)) return PW_E_ARG;
    pw_status_t st = check_func_shape(f->blocks, f->block_count, f->insts, f->inst_count);
    if (st != PW_OK) return st;
    pw_ir_block_t *b = sorted_blocks_copy(f);
    if (!b) return PW_E_NOMEM;
    digest_blocks_insts(b, f->block_count, f->insts, f->inst_count, out);
    free(b);
    return PW_OK;
}

/* ---------------------------------------------------------------- write -- */

typedef struct {
    pw_ir_func_hdr_t hdr;
    const pw_func_input_t *src;
} func_slot_t;

static int qs_func_slot(const void *a, const void *b) {
    return func_cmp(&((const func_slot_t *)a)->hdr, &((const func_slot_t *)b)->hdr);
}

pw_status_t pw_bundle_write(const pw_bundle_input_t *in, uint8_t **out, size_t *out_len) {
    if (!in || !out || !out_len) return PW_E_ARG;
    *out = NULL;
    *out_len = 0;
    if ((in->binary_len && !in->binary) || (in->alloy_len && !in->alloy_model) ||
        (in->func_count && !in->funcs) || (in->record_count && !in->records)) return PW_E_ARG;
    if (in->container_format < 1 || in->container_format > 3 || in->arch > PW_ARCH_AARCH64)
        return PW_E_BAD_ENUM;
    if (!utf8_ok(in->alloy_model, in->alloy_len)) return PW_E_UTF8;

    pw_status_t st = PW_OK;
    func_slot_t *slots = NULL;
    pw_evidence_record_t *recs = NULL;
    uint8_t *buf = NULL;

    /* Functions: compute canonical digests, then sort. */
    size_t total_ir = PW_IR_CORPUS_HDR_BYTES;
    slots = (func_slot_t *)calloc(in->func_count ? in->func_count : 1, sizeof *slots);
    if (!slots) { st = PW_E_NOMEM; goto done; }
    for (uint32_t i = 0; i < in->func_count; ++i) {
        const pw_func_input_t *f = &in->funcs[i];
        slots[i].src = f;
        slots[i].hdr = f->hdr;
        slots[i].hdr.block_count = f->block_count;
        slots[i].hdr.inst_count = f->inst_count;
        slots[i].hdr._reserved = 0;
        st = (pw_status_t)pw_func_ir_digest(f, slots[i].hdr.ir_sha256);
        if (st != PW_OK) goto done;
        total_ir += PW_FUNC_HDR_BYTES + (size_t)f->block_count * PW_BLOCK_BYTES +
                    (size_t)f->inst_count * PW_INST_BYTES;
    }
    if (in->func_count > 1) qsort(slots, in->func_count, sizeof *slots, qs_func_slot);

    /* Records: validate, check links, sort. */
    recs = (pw_evidence_record_t *)malloc((in->record_count ? in->record_count : 1) * sizeof *recs);
    if (!recs) { st = PW_E_NOMEM; goto done; }
    for (uint32_t i = 0; i < in->record_count; ++i) {
        recs[i] = in->records[i];
        recs[i]._pad0 = 0;
        recs[i]._reserved = 0;
        st = record_semantics(&recs[i]);
        if (st != PW_OK) goto done;
        if (!is_zero32(recs[i].func_ir_sha256)) {
            int found = 0;
            for (uint32_t k = 0; k < in->func_count && !found; ++k)
                found = memcmp(slots[k].hdr.ir_sha256, recs[i].func_ir_sha256, 32) == 0;
            if (!found) { st = PW_E_DANGLING_FUNC_REF; goto done; }
        }
    }
    pw_sort_records(recs, in->record_count);

    size_t rec_bytes = (size_t)in->record_count * PW_RECORD_BYTES;
    size_t total = PW_MANIFEST_BYTES + rec_bytes + total_ir + in->alloy_len;
    buf = (uint8_t *)calloc(total ? total : 1, 1);
    if (!buf) { st = PW_E_NOMEM; goto done; }

    size_t off = PW_MANIFEST_BYTES;
    for (uint32_t i = 0; i < in->record_count; ++i, off += PW_RECORD_BYTES)
        pw_serialize_evidence_record(&recs[i], buf + off);

    size_t ir_off = off;
    wr32(buf + off, PW_IR_MAGIC);
    wr32(buf + off + 4, PW_IR_VERSION);
    wr32(buf + off + 8, in->func_count);
    wr32(buf + off + 12, 0);
    off += PW_IR_CORPUS_HDR_BYTES;
    for (uint32_t i = 0; i < in->func_count; ++i) {
        const pw_func_input_t *f = slots[i].src;
        pw_serialize_func_hdr(&slots[i].hdr, buf + off);
        off += PW_FUNC_HDR_BYTES;
        pw_ir_block_t *b = sorted_blocks_copy(f);
        if (!b) { st = PW_E_NOMEM; goto done; }
        for (uint32_t k = 0; k < f->block_count; ++k, off += PW_BLOCK_BYTES)
            pw_serialize_ir_block(&b[k], buf + off);
        free(b);
        for (uint32_t k = 0; k < f->inst_count; ++k, off += PW_INST_BYTES)
            pw_serialize_ir_inst(&f->insts[k], buf + off);
    }
    size_t ir_end = off;
    if (in->alloy_len) memcpy(buf + off, in->alloy_model, in->alloy_len);

    pw_evidence_manifest_t m;
    memset(&m, 0, sizeof m);
    m.magic = PW_EVIDENCE_MAGIC;
    m.version = PW_EVIDENCE_VERSION;
    m.container_format = in->container_format;
    m.arch = in->arch;
    m.overall_verdict = pw_derive_overall_verdict(recs, in->record_count);
    m.record_count = in->record_count;
    m.binary_size_bytes = (uint64_t)in->binary_len;
    pw_sha256(in->binary, in->binary_len, m.binary_sha256);
    pw_sha256(buf + ir_off, ir_end - ir_off, m.ir_corpus_sha256);
    pw_sha256(in->alloy_model, in->alloy_len, m.alloy_model_sha256);
    pw_sha256(buf + PW_MANIFEST_BYTES, rec_bytes, m.records_sha256);
    pw_serialize_manifest(&m, buf);
    pw_sha256(buf, PW_MANIFEST_SEALED_BYTES, m.manifest_sha256);
    memcpy(buf + PW_MANIFEST_SEALED_BYTES, m.manifest_sha256, 32);

    *out = buf;
    *out_len = total;
    buf = NULL;
done:
    free(buf);
    free(recs);
    free(slots);
    return st;
}

/* --------------------------------------------------------------- verify -- */

#define FAIL(code, at) do { if (rep) rep->fail_offset = (at); return (code); } while (0)

pw_status_t pw_bundle_verify(const uint8_t *bundle, size_t len,
                             const uint8_t *binary, size_t binary_len,
                             pw_verify_report_t *report) {
    pw_verify_report_t local;
    pw_verify_report_t *rep = report ? report : &local;
    memset(rep, 0, sizeof *rep);
    uint8_t d[32];

    if (!bundle) return PW_E_ARG;
    if (len < PW_MANIFEST_BYTES) FAIL(PW_E_TRUNCATED, len);
    pw_evidence_manifest_t *m = &rep->manifest;
    pw_parse_manifest(bundle, m);

    /* 1. Manifest seal over bytes [0, 160). */
    pw_sha256(bundle, PW_MANIFEST_SEALED_BYTES, d);
    if (memcmp(d, m->manifest_sha256, 32) != 0) FAIL(PW_E_MANIFEST_DIGEST, PW_MANIFEST_SEALED_BYTES);
    if (m->magic != PW_EVIDENCE_MAGIC) FAIL(PW_E_MAGIC, 0);
    if (m->version != PW_EVIDENCE_VERSION) FAIL(PW_E_VERSION, 4);
    if (m->_pad0 != 0) FAIL(PW_E_NONZERO_PAD, 11);
    if (m->_reserved1 != 0) FAIL(PW_E_NONZERO_PAD, 152);
    if (m->container_format < 1 || m->container_format > 3) FAIL(PW_E_BAD_ENUM, 8);
    if (m->arch > PW_ARCH_AARCH64) FAIL(PW_E_BAD_ENUM, 9);
    if (!verdict_ok(m->overall_verdict)) FAIL(PW_E_BAD_ENUM, 10);

    /* 2. Records. */
    size_t avail = len - PW_MANIFEST_BYTES;
    if ((uint64_t)m->record_count * PW_RECORD_BYTES > avail) FAIL(PW_E_TRUNCATED, len);
    rep->records_off = PW_MANIFEST_BYTES;
    rep->records_end = PW_MANIFEST_BYTES + (size_t)m->record_count * PW_RECORD_BYTES;
    pw_sha256(bundle + rep->records_off, rep->records_end - rep->records_off, d);
    if (memcmp(d, m->records_sha256, 32) != 0) FAIL(PW_E_RECORDS_DIGEST, rep->records_off);

    /* 3. IR corpus. */
    size_t off = rep->records_end;
    rep->ir_off = off;
    if (len - off < PW_IR_CORPUS_HDR_BYTES) FAIL(PW_E_TRUNCATED, len);
    if (rd32(bundle + off) != PW_IR_MAGIC) FAIL(PW_E_MAGIC, off);
    if (rd32(bundle + off + 4) != PW_IR_VERSION) FAIL(PW_E_VERSION, off + 4);
    rep->func_count = rd32(bundle + off + 8);
    if (rd32(bundle + off + 12) != 0) FAIL(PW_E_NONZERO_PAD, off + 12);
    off += PW_IR_CORPUS_HDR_BYTES;

    /* Walk functions to find ir_end, checking canonical form as we go. */
    size_t funcs_off = off;
    pw_ir_func_hdr_t prev_hdr;
    memset(&prev_hdr, 0, sizeof prev_hdr);
    for (uint32_t i = 0; i < rep->func_count; ++i) {
        if (len - off < PW_FUNC_HDR_BYTES) FAIL(PW_E_TRUNCATED, len);
        pw_ir_func_hdr_t h;
        pw_parse_func_hdr(bundle + off, &h);
        size_t hdr_off = off;
        if (h._reserved != 0) FAIL(PW_E_NONZERO_PAD, off + 56);
        if (i > 0 && func_cmp(&prev_hdr, &h) > 0) FAIL(PW_E_NOT_SORTED, off);
        prev_hdr = h;
        off += PW_FUNC_HDR_BYTES;
        uint64_t need = (uint64_t)h.block_count * PW_BLOCK_BYTES + (uint64_t)h.inst_count * PW_INST_BYTES;
        if (need > (uint64_t)(len - off)) FAIL(PW_E_TRUNCATED, len);
        size_t body = off;
        pw_ir_block_t prev_b;
        memset(&prev_b, 0, sizeof prev_b);
        for (uint32_t k = 0; k < h.block_count; ++k, off += PW_BLOCK_BYTES) {
            pw_ir_block_t b, c;
            pw_parse_ir_block(bundle + off, &b);
            c = b;
            canon_block(&c);
            if (b.succ_count > 2 || memcmp(&b, &c, sizeof b) != 0) FAIL(PW_E_NOT_CANONICAL, off);
            if ((uint64_t)b.first_inst + b.inst_count > h.inst_count) FAIL(PW_E_NOT_CANONICAL, off);
            if (k > 0 && block_cmp(&prev_b, &b) > 0) FAIL(PW_E_NOT_SORTED, off);
            prev_b = b;
        }
        uint32_t prev_ssa = 0;
        for (uint32_t k = 0; k < h.inst_count; ++k, off += PW_INST_BYTES) {
            pw_ir_inst_t ins;
            uint8_t re[64];
            pw_parse_ir_inst(bundle + off, &ins);
            pw_serialize_ir_inst(&ins, re);
            if (memcmp(re, bundle + off, 64) != 0) FAIL(PW_E_NOT_CANONICAL, off);
            if (k > 0 && ins.ssa_id <= prev_ssa) FAIL(PW_E_NOT_SORTED, off);
            prev_ssa = ins.ssa_id;
        }
        pw_sha256(bundle + body, off - body, d);
        if (memcmp(d, h.ir_sha256, 32) != 0) FAIL(PW_E_FUNC_DIGEST, hdr_off + 24);
    }
    rep->ir_end = off;
    pw_sha256(bundle + rep->ir_off, rep->ir_end - rep->ir_off, d);
    if (memcmp(d, m->ir_corpus_sha256, 32) != 0) FAIL(PW_E_IR_DIGEST, rep->ir_off);

    /* 4. Alloy model. */
    rep->alloy_off = off;
    pw_sha256(bundle + off, len - off, d);
    if (memcmp(d, m->alloy_model_sha256, 32) != 0) FAIL(PW_E_ALLOY_DIGEST, off);
    if (!utf8_ok(bundle + off, len - off)) FAIL(PW_E_UTF8, off);

    /* 5. Record semantics, order, verdict, and links to Gate 3 digests. */
    pw_evidence_record_t prev_r;
    memset(&prev_r, 0, sizeof prev_r);
    uint8_t worst = m->record_count ? PW_VERDICT_PROVEN_COMPLIANT : PW_VERDICT_UNKNOWN;
    for (uint32_t i = 0; i < m->record_count; ++i) {
        size_t ro = rep->records_off + (size_t)i * PW_RECORD_BYTES;
        pw_evidence_record_t r;
        uint8_t re[64];
        pw_parse_evidence_record(bundle + ro, &r);
        pw_serialize_evidence_record(&r, re);
        if (memcmp(re, bundle + ro, 64) != 0) FAIL(PW_E_NONZERO_PAD, ro);
        pw_status_t st = record_semantics(&r);
        if (st != PW_OK) FAIL(st, ro);
        if (i > 0 && pw_record_cmp(&prev_r, &r) > 0) FAIL(PW_E_NOT_SORTED, ro);
        prev_r = r;
        if (r.verdict == PW_VERDICT_PROVEN_VULNERABLE) worst = PW_VERDICT_PROVEN_VULNERABLE;
        else if (r.verdict == PW_VERDICT_UNKNOWN && worst != PW_VERDICT_PROVEN_VULNERABLE)
            worst = PW_VERDICT_UNKNOWN;
        if (!is_zero32(r.func_ir_sha256)) {
            int found = 0;
            size_t fo = funcs_off;
            for (uint32_t k = 0; k < rep->func_count && !found; ++k) {
                found = memcmp(bundle + fo + 24, r.func_ir_sha256, 32) == 0;
                fo += PW_FUNC_HDR_BYTES + (size_t)rd32(bundle + fo + 4) * PW_BLOCK_BYTES +
                      (size_t)rd32(bundle + fo + 8) * PW_INST_BYTES;
            }
            if (!found) FAIL(PW_E_DANGLING_FUNC_REF, ro + 24);
        }
    }
    if (m->overall_verdict != worst) FAIL(PW_E_VERDICT, 10);

    /* 6. Optional: recompute the Gate 1 binary digest. */
    if (binary) {
        if ((uint64_t)binary_len != m->binary_size_bytes) FAIL(PW_E_BINARY_SIZE, 16);
        pw_sha256(binary, binary_len, d);
        if (memcmp(d, m->binary_sha256, 32) != 0) FAIL(PW_E_BINARY_DIGEST, 24);
    }
    return PW_OK;
}

const char *pw_status_str(pw_status_t s) {
    static const char *names[PW_E_COUNT] = {
        "OK", "out of memory", "bad argument", "truncated bundle", "bad magic",
        "bad version", "nonzero padding/reserved field", "invalid enum value",
        "manifest_sha256 mismatch", "records_sha256 mismatch", "ir_corpus_sha256 mismatch",
        "function ir_sha256 mismatch", "alloy_model_sha256 mismatch", "binary_sha256 mismatch",
        "binary_size_bytes mismatch", "non-canonical encoding", "not in canonical sort order",
        "overall_verdict does not match records", "unknown_reason inconsistent with verdict",
        "record references a function digest not in the bundle", "Alloy model is not valid UTF-8"
    };
    return ((unsigned)s < (unsigned)PW_E_COUNT) ? names[s] : "unrecognized status";
}
