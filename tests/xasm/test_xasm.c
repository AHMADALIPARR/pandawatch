/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Tests for pw-xasm: known encodings, assemble/disassemble round trips,
 * random-byte decode round trips, the FORTRAN 77 struct parser against the C
 * layout and parsers, and the lifter against the bundle verifier. C23.
 * argv[1] = tests/xasm/corpus.s */
#include "pw_fortran.h"
#include "pw_io.h"
#include "pw_x86.h"
#include "pw_xray_canon.h"
#include "pw_xray_demo.h"
#include "pw_test.h"

#include <math.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

constexpr uint64_t BASE = 0x401000;

/* ---------------------------------------------------------------- x86 -- */

typedef struct {
    const char *text;
    size_t      len;
    uint8_t     bytes[15];
} known_t;

static const known_t known[] = {
    { "mov rax, rbx",                 3, { 0x48, 0x89, 0xd8 } },
    { "sub rsp, 8",                   4, { 0x48, 0x83, 0xec, 0x08 } },
    { "mov r8, [rsp+8]",              5, { 0x4c, 0x8b, 0x44, 0x24, 0x08 } },
    { "call r11",                     3, { 0x41, 0xff, 0xd3 } },
    { "mov rax, [rip+0x10]",          7, { 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00 } },
    { "lea rax, [rcx*4]",             8, { 0x48, 0x8d, 0x04, 0x8d, 0x00, 0x00, 0x00, 0x00 } },
    { "push rbp",                     1, { 0x55 } },
    { "pop r15",                      2, { 0x41, 0x5f } },
    { "ret",                          1, { 0xc3 } },
    { "xor eax, eax",                 2, { 0x31, 0xc0 } },
    { "mov eax, 1",                   5, { 0xb8, 0x01, 0x00, 0x00, 0x00 } },
    { "movabs rax, 0x1122334455667788", 10, { 0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 } },
    { "mov rax, -1",                  7, { 0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff } },
    { "add eax, 0x100",               6, { 0x81, 0xc0, 0x00, 0x01, 0x00, 0x00 } },
    { "cmp qword ptr [rbp-8], 0",     5, { 0x48, 0x83, 0x7d, 0xf8, 0x00 } },
    { "mov rax, [rbp]",               4, { 0x48, 0x8b, 0x45, 0x00 } },
    { "mov rax, [r12]",               4, { 0x49, 0x8b, 0x04, 0x24 } },
    { "test rdi, rdi",                3, { 0x48, 0x85, 0xff } },
    { "jmp qword ptr [rax*8+0x1000]", 7, { 0xff, 0x24, 0xc5, 0x00, 0x10, 0x00, 0x00 } },
    { "call 0x401000",                5, { 0xe8, 0xfb, 0xff, 0xff, 0xff } },
    { "jne short 0x401000",           2, { 0x75, 0xfe } },
    { "je 0x401000",                  6, { 0x0f, 0x84, 0xfa, 0xff, 0xff, 0xff } },
    { "int3",                         1, { 0xcc } },
    { "nop",                          1, { 0x90 } },
};

static void test_known(void) {
    for (size_t i = 0; i < sizeof known / sizeof known[0]; i++) {
        uint8_t *out = nullptr;
        size_t len = 0;
        char err[128];
        const int rc = pw_x86_assemble(known[i].text, BASE, &out, &len, err, sizeof err);
        CHECK(rc == 0);
        if (rc != 0) { fprintf(stderr, "  %s: %s\n", known[i].text, err); continue; }
        CHECK(len == known[i].len && memcmp(out, known[i].bytes, len) == 0);
        pw_x86_insn_t d;
        CHECK(pw_x86_decode(known[i].bytes, known[i].len, &d) == known[i].len);
        CHECK(d.length == known[i].len);
        free(out);
    }
    /* Decoder rejects bytes outside the subset and truncated input. */
    static const uint8_t bad[][3] = { { 0x0f, 0x05 }, { 0x62 }, { 0xff, 0xc0 }, { 0x48, 0x90 } };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        pw_x86_insn_t d;
        CHECK(pw_x86_decode(bad[i], 3, &d) == 0);
    }
    pw_x86_insn_t d;
    CHECK(pw_x86_decode(known[11].bytes, 9, &d) == 0);
}

static char *disassemble_text(const uint8_t *code, size_t len, uint64_t base, size_t *ninsn) {
    char *text = malloc(len * 64 + 1);
    size_t n = 0;
    *ninsn = 0;
    for (size_t off = 0; off < len;) {
        pw_x86_insn_t d;
        const size_t l = pw_x86_decode(code + off, len - off, &d);
        if (l == 0) { free(text); return nullptr; }
        const int w = pw_x86_format(&d, base + off, text + n, 63);
        if (w < 0) { free(text); return nullptr; }
        n += (size_t)w;
        text[n++] = '\n';
        off += l;
        (*ninsn)++;
    }
    text[n] = '\0';
    return text;
}

static size_t corpus_insns;

static void test_corpus_roundtrip(const char *path) {
    uint8_t *src = nullptr;
    size_t n = 0;
    CHECK(pw_read_file(path, &src, &n) == 0);
    if (src == nullptr) return;
    char *text = malloc(n + 1);
    memcpy(text, src, n);
    text[n] = '\0';
    free(src);
    uint8_t *a = nullptr, *b = nullptr;
    size_t alen = 0, blen = 0;
    char err[256];
    CHECK(pw_x86_assemble(text, BASE, &a, &alen, err, sizeof err) == 0);
    if (a == nullptr) { fprintf(stderr, "  corpus: %s\n", err); free(text); return; }
    char *dis = disassemble_text(a, alen, BASE, &corpus_insns);
    CHECK(dis != nullptr);
    if (dis) {
        CHECK(pw_x86_assemble(dis, BASE, &b, &blen, err, sizeof err) == 0);
        CHECK(blen == alen && b && memcmp(a, b, alen) == 0);
        if (blen != alen) fprintf(stderr, "  corpus reassembly: %s\n", err);
    }
    printf("corpus: %zu instructions, %zu bytes, assemble/disassemble/reassemble identical\n",
           corpus_insns, alen);
    free(dis);
    free(b);
    free(a);
    free(text);
}

static uint64_t rng = 0x9E3779B97F4A7C15u;
static uint64_t next_rand(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

/* decode -> format -> assemble -> decode -> format must give the same text,
 * for every decodable random byte string. */
static void test_random_roundtrip(void) {
    static const uint8_t first[] = {
        0x01, 0x03, 0x09, 0x0b, 0x21, 0x23, 0x29, 0x2b, 0x31, 0x33, 0x39, 0x3b, 0x85, 0x89,
        0x8b, 0x8d, 0xff, 0x83, 0x81, 0xc7, 0x50, 0x5b, 0xb8, 0xbf, 0x74, 0xeb, 0xe8, 0xe9,
        0x0f, 0x90, 0xc3, 0xcc
    };
    size_t decoded = 0, mismatches = 0;
    for (int iter = 0; iter < 200000; iter++) {
        uint8_t buf[16];
        for (size_t k = 0; k < sizeof buf; k++) buf[k] = (uint8_t)next_rand();
        size_t p = 0;
        if (next_rand() & 1) buf[p++] = (uint8_t)(0x40 | (next_rand() & 0x0f));
        buf[p] = first[next_rand() % sizeof first];
        if (buf[p] == 0x0f) buf[p + 1] = (uint8_t)(0x80 | (next_rand() & 0x0f));
        pw_x86_insn_t d1, d2;
        if (pw_x86_decode(buf, sizeof buf, &d1) == 0) continue;
        decoded++;
        char t1[128], t2[128];
        if (pw_x86_format(&d1, BASE, t1, sizeof t1) < 0) { mismatches++; continue; }
        uint8_t *out = nullptr;
        size_t len = 0;
        char err[128];
        if (pw_x86_assemble(t1, BASE, &out, &len, err, sizeof err) != 0 ||
            pw_x86_decode(out, len, &d2) != len ||
            pw_x86_format(&d2, BASE, t2, sizeof t2) < 0 || strcmp(t1, t2) != 0) {
            if (mismatches < 5) fprintf(stderr, "  random mismatch: '%s' (%s)\n", t1, err);
            mismatches++;
        }
        free(out);
    }
    CHECK(decoded > 50000);
    CHECK(mismatches == 0);
    printf("random: %zu decodable byte strings, %zu text mismatches\n", decoded, mismatches);
}

/* ------------------------------------------------------------ Fortran -- */

typedef struct { int32_t kind; size_t off, size; } cfield_t;

#define F(k, T, m) { k, offsetof(T, m), sizeof(((T *)nullptr)->m) }
#define FS(k, T, a, m) { k, offsetof(T, a) + offsetof(pw_operand_t, m), sizeof(((pw_operand_t *)nullptr)->m) }
static const cfield_t cfields[] = {
    F(1, pw_operand_t, kind), F(1, pw_operand_t, type), F(1, pw_operand_t, _pad0),
    F(1, pw_operand_t, ref_id), F(1, pw_operand_t, imm_val),
    F(2, pw_ir_inst_t, ssa_id), F(2, pw_ir_inst_t, opcode), F(2, pw_ir_inst_t, out_type),
    F(2, pw_ir_inst_t, flags), F(2, pw_ir_inst_t, source_va),
    FS(2, pw_ir_inst_t, src[0], kind), FS(2, pw_ir_inst_t, src[0], type),
    FS(2, pw_ir_inst_t, src[0], _pad0), FS(2, pw_ir_inst_t, src[0], ref_id),
    FS(2, pw_ir_inst_t, src[0], imm_val),
    FS(2, pw_ir_inst_t, src[1], kind), FS(2, pw_ir_inst_t, src[1], type),
    FS(2, pw_ir_inst_t, src[1], _pad0), FS(2, pw_ir_inst_t, src[1], ref_id),
    FS(2, pw_ir_inst_t, src[1], imm_val),
    FS(2, pw_ir_inst_t, src[2], kind), FS(2, pw_ir_inst_t, src[2], type),
    FS(2, pw_ir_inst_t, src[2], _pad0), FS(2, pw_ir_inst_t, src[2], ref_id),
    FS(2, pw_ir_inst_t, src[2], imm_val),
    F(3, pw_ir_block_t, block_id), F(3, pw_ir_block_t, first_inst), F(3, pw_ir_block_t, inst_count),
    F(3, pw_ir_block_t, succ_count), { 3, offsetof(pw_ir_block_t, succ_blocks), 4 },
    { 3, offsetof(pw_ir_block_t, succ_blocks) + 4, 4 }, F(3, pw_ir_block_t, start_va),
    F(4, pw_ir_func_hdr_t, func_id), F(4, pw_ir_func_hdr_t, block_count),
    F(4, pw_ir_func_hdr_t, inst_count), F(4, pw_ir_func_hdr_t, stack_frame_bytes),
    F(4, pw_ir_func_hdr_t, entry_va), F(4, pw_ir_func_hdr_t, ir_sha256),
    F(4, pw_ir_func_hdr_t, _reserved),
    F(5, pw_evidence_record_t, record_id), F(5, pw_evidence_record_t, verdict),
    F(5, pw_evidence_record_t, _pad0), F(5, pw_evidence_record_t, rule_id),
    F(5, pw_evidence_record_t, unknown_reason), F(5, pw_evidence_record_t, detected_bytes),
    F(5, pw_evidence_record_t, required_bytes), F(5, pw_evidence_record_t, site_va),
    F(5, pw_evidence_record_t, func_ir_sha256), F(5, pw_evidence_record_t, _reserved),
    F(6, pw_evidence_manifest_t, magic), F(6, pw_evidence_manifest_t, version),
    F(6, pw_evidence_manifest_t, container_format), F(6, pw_evidence_manifest_t, arch),
    F(6, pw_evidence_manifest_t, overall_verdict), F(6, pw_evidence_manifest_t, _pad0),
    F(6, pw_evidence_manifest_t, record_count), F(6, pw_evidence_manifest_t, binary_size_bytes),
    F(6, pw_evidence_manifest_t, binary_sha256), F(6, pw_evidence_manifest_t, ir_corpus_sha256),
    F(6, pw_evidence_manifest_t, alloy_model_sha256), F(6, pw_evidence_manifest_t, records_sha256),
    F(6, pw_evidence_manifest_t, _reserved1), F(6, pw_evidence_manifest_t, manifest_sha256),
};
static const size_t struct_size[7] = { 0, sizeof(pw_operand_t), sizeof(pw_ir_inst_t),
    sizeof(pw_ir_block_t), sizeof(pw_ir_func_hdr_t), sizeof(pw_evidence_record_t),
    sizeof(pw_evidence_manifest_t) };

static void test_fortran_layout(void) {
    size_t idx = 0;
    for (int32_t kind = 1; kind <= 6; kind++) {
        int32_t nf = 0, ksiz = 0, ipad = 0, ierr = 0;
        const int32_t zero = 0;
        pwlayt_(&kind, &zero, &nf, &ksiz, &ipad, &ierr);
        CHECK(ierr == 0 && (size_t)ksiz == struct_size[kind]);
        size_t covered = 0;
        for (int32_t i = 1; i <= nf; i++, idx++) {
            int32_t ioff = 0, isiz = 0;
            pwlayt_(&kind, &i, &ioff, &isiz, &ipad, &ierr);
            CHECK(ierr == 0 && idx < sizeof cfields / sizeof cfields[0]);
            if (idx >= sizeof cfields / sizeof cfields[0]) return;
            CHECK(cfields[idx].kind == kind);
            CHECK((size_t)ioff == cfields[idx].off && (size_t)isiz == cfields[idx].size);
            covered += (size_t)isiz;
        }
        CHECK(covered == struct_size[kind]);   /* no implicit padding */
    }
    CHECK(idx == sizeof cfields / sizeof cfields[0]);
    const int32_t badk = 7, one = 1;
    int32_t o, s, p, e;
    pwlayt_(&badk, &one, &o, &s, &p, &e);
    CHECK(e == 1);
}

/* Fortran decode equals the C parser; Fortran encode reproduces the bytes. */
static void check_struct_roundtrip(int32_t kind, const uint8_t *bytes) {
    int64_t vals[PWF_MAX_VALS];
    int32_t nv = 0, ierr = 0, ibad = 0;
    const int32_t nb = (int32_t)struct_size[kind];
    pwdec_(&kind, bytes, &nb, vals, &nv, &ierr);
    CHECK(ierr == 0);
    uint8_t re[192];
    memset(re, 0xAA, sizeof re);
    pwenc_(&kind, vals, re, &nb, &ierr);
    CHECK(ierr == 0 && memcmp(re, bytes, (size_t)nb) == 0);
    pwval_(&kind, bytes, &nb, &ibad, &ierr);
    CHECK(ierr == 0 && ibad == 0);
}

static void test_fortran_structs(void) {
    static const uint8_t binary[] = "pw-xasm test binary";
    static const uint8_t alloy[] = "module t\n";
    pw_demo_t demo;
    CHECK(pw_demo_build(&demo, binary, sizeof binary - 1, alloy, sizeof alloy - 1) == PW_OK);
    uint8_t *bundle = nullptr;
    size_t blen = 0;
    CHECK(pw_bundle_write(&demo.input, &bundle, &blen) == PW_OK);
    if (bundle == nullptr) return;

    check_struct_roundtrip(PWF_MANIFEST, bundle);
    pw_evidence_manifest_t m;
    pw_parse_manifest(bundle, &m);
    int64_t vals[PWF_MAX_VALS];
    int32_t nv = 0, ierr = 0;
    const int32_t kman = PWF_MANIFEST, nman = 192;
    pwdec_(&kman, bundle, &nman, vals, &nv, &ierr);
    CHECK(nv == 29);
    CHECK((uint64_t)vals[0] == m.magic && (uint64_t)vals[1] == m.version);
    CHECK((uint64_t)vals[6] == m.record_count && (uint64_t)vals[7] == m.binary_size_bytes);
    uint64_t lane0 = 0;
    for (int k = 0; k < 8; k++) lane0 |= (uint64_t)m.binary_sha256[k] << (8 * k);
    CHECK((uint64_t)vals[8] == lane0);

    size_t off = PW_MANIFEST_BYTES;
    for (uint32_t r = 0; r < m.record_count; r++, off += PW_RECORD_BYTES) {
        check_struct_roundtrip(PWF_RECORD, bundle + off);
        pw_evidence_record_t rec;
        pw_parse_evidence_record(bundle + off, &rec);
        const int32_t k = PWF_RECORD, n = 64;
        pwdec_(&k, bundle + off, &n, vals, &nv, &ierr);
        CHECK(nv == 13 && (uint64_t)vals[0] == rec.record_id && (uint64_t)vals[3] == rec.rule_id &&
              (uint64_t)vals[7] == rec.site_va);
    }
    off += PW_IR_CORPUS_HDR_BYTES;
    size_t structs = 1 + m.record_count;
    for (int f = 0; f < 2; f++) {
        pw_ir_func_hdr_t h;
        pw_parse_func_hdr(bundle + off, &h);
        check_struct_roundtrip(PWF_FUNC_HDR, bundle + off);
        off += PW_FUNC_HDR_BYTES;
        structs++;
        for (uint32_t k = 0; k < h.block_count; k++, off += PW_BLOCK_BYTES, structs++)
            check_struct_roundtrip(PWF_BLOCK, bundle + off);
        for (uint32_t k = 0; k < h.inst_count; k++, off += PW_INST_BYTES, structs++) {
            check_struct_roundtrip(PWF_INST, bundle + off);
            for (int s = 0; s < 3; s++) check_struct_roundtrip(PWF_OPERAND, bundle + off + 16 + 16 * s);
            pw_ir_inst_t in;
            pw_parse_ir_inst(bundle + off, &in);
            const int32_t ki = PWF_INST, ni = 64;
            pwdec_(&ki, bundle + off, &ni, vals, &nv, &ierr);
            CHECK(nv == 20 && (uint64_t)vals[0] == in.ssa_id && (uint64_t)vals[1] == in.opcode &&
                  (uint64_t)vals[4] == in.source_va && (uint64_t)vals[8] == in.src[0].ref_id);
        }
    }
    printf("fortran: %zu structs from the demo bundle decode/encode byte-identical\n", structs);

    /* Nonzero padding is reported by field index; the encoder zeroes it. */
    uint8_t rec[64];
    memcpy(rec, bundle + PW_MANIFEST_BYTES, 64);
    rec[5] = 0x01;          /* _pad0 */
    const int32_t krec = PWF_RECORD, n64 = 64;
    int32_t ibad = 0;
    pwval_(&krec, rec, &n64, &ibad, &ierr);
    CHECK(ibad == 3);
    rec[5] = 0;
    rec[60] = 0x80;         /* _reserved */
    pwval_(&krec, rec, &n64, &ibad, &ierr);
    CHECK(ibad == 10);
    pwdec_(&krec, rec, &n64, vals, &nv, &ierr);
    uint8_t clean[64];
    pwenc_(&krec, vals, clean, &n64, &ierr);
    pwval_(&krec, clean, &n64, &ibad, &ierr);
    CHECK(ibad == 0 && clean[60] == 0);
    uint8_t man[192];
    memcpy(man, bundle, 192);
    man[155] = 0x7F;        /* _reserved1 */
    pwval_(&kman, man, &nman, &ibad, &ierr);
    CHECK(ibad == 13);
    const int32_t short_len = 100;
    pwval_(&kman, man, &short_len, &ibad, &ierr);
    CHECK(ierr == 2);

    /* Field names. */
    char name[20];
    const int32_t i13 = 13;
    pwfnam_(&kman, &i13, name, sizeof name);
    CHECK(memcmp(name, "_reserved1          ", 20) == 0);
    free(bundle);
}

static void test_fortran_numeric(void) {
    const uint8_t wiki[] = "Wikipedia";
    const int32_t n = 9, zero = 0;
    CHECK(pwadl_(wiki, &n) == 0x11E60398);
    CHECK(pwadl_(wiki, &zero) == 1);
    uint8_t big[70000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(255 - (i % 7));
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < sizeof big; i++) { a = (a + big[i]) % 65521; b = (b + a) % 65521; }
    const int32_t nbig = (int32_t)sizeof big;
    CHECK((uint64_t)pwadl_(big, &nbig) == ((uint64_t)b << 16 | a));

    /* Little-endian get/put of every width with high bits set. */
    uint8_t buf[16] = { 0 };
    for (int32_t w = 1; w <= 8; w++) {
        const int64_t v = (int64_t)0xF1E2D3C4B5A69788u;
        const int32_t off = 3;
        pwputn_(buf, &off, &w, &v);
        const uint64_t mask = w == 8 ? UINT64_MAX : (((uint64_t)1 << (8 * w)) - 1);
        CHECK((uint64_t)pwgetn_(buf, &off, &w) == ((uint64_t)v & mask));
    }

    /* Record statistics against a C reference. */
    enum { NREC = 37 };
    pw_evidence_record_t recs[NREC];
    uint8_t packed[NREC * 64];
    int32_t want[11] = { 0 };
    double sd = 0, sr = 0, mind = 1e300, maxd = -1, minr = 1e300, maxr = -1, short_total = 0;
    for (int i = 0; i < NREC; i++) {
        memset(&recs[i], 0, sizeof recs[i]);
        recs[i].record_id = (uint32_t)i;
        recs[i].verdict = (uint8_t)(1 + (i % 4 == 3 ? 2 : i % 3));
        if (i == 5) recs[i].verdict = 9;
        recs[i].unknown_reason = recs[i].verdict == 3 ? (uint16_t)(1 + i % 5) : 0;
        recs[i].detected_bytes = (uint16_t)(32 * (i % 9) + 1);
        recs[i].required_bytes = (uint32_t)(1184 + 97 * (i % 11));
        if (i % 6 == 0) recs[i].required_bytes = recs[i].detected_bytes;
        pw_serialize_evidence_record(&recs[i], packed + 64 * i);
        if (i == 7) packed[64 * i + 5] = 1;
        const uint8_t v = recs[i].verdict;
        if (v >= 1 && v <= 3) want[v - 1]++; else want[9]++;
        if (recs[i].unknown_reason) want[2 + recs[i].unknown_reason]++;
        const double d = recs[i].detected_bytes, r = recs[i].required_bytes;
        if (r > d) { want[8]++; short_total += r - d; }
        sd += d; sr += r;
        mind = fmin(mind, d); maxd = fmax(maxd, d); minr = fmin(minr, r); maxr = fmax(maxr, r);
    }
    want[10] = 1;
    const double meand = sd / NREC, meanr = sr / NREC;
    double vd = 0, vr = 0;
    for (int i = 0; i < NREC; i++) {
        vd += (recs[i].detected_bytes - meand) * (recs[i].detected_bytes - meand);
        vr += (recs[i].required_bytes - meanr) * (recs[i].required_bytes - meanr);
    }
    vd /= NREC;
    vr /= NREC;
    int32_t istat[11];
    double dstat[9];
    const int32_t nrec = NREC;
    pwrst_(packed, &nrec, istat, dstat);
    for (int k = 0; k < 11; k++) CHECK(istat[k] == want[k]);
    CHECK(fabs(dstat[0] - meand) < 1e-9 && fabs(dstat[1] - vd) < 1e-6);
    CHECK(dstat[2] == mind && dstat[3] == maxd);
    CHECK(fabs(dstat[4] - meanr) < 1e-9 && fabs(dstat[5] - vr) < 1e-6);
    CHECK(dstat[6] == minr && dstat[7] == maxr && dstat[8] == short_total);
}

/* --------------------------------------------------------------- lift -- */

static void test_lift(const char *corpus_path) {
    uint8_t *src = nullptr;
    size_t n = 0;
    if (pw_read_file(corpus_path, &src, &n) != 0) { CHECK(false); return; }
    char *text = malloc(n + 1);
    memcpy(text, src, n);
    text[n] = '\0';
    free(src);
    uint8_t *code = nullptr;
    size_t len = 0;
    char err[128];
    CHECK(pw_x86_assemble(text, BASE, &code, &len, err, sizeof err) == 0);
    free(text);
    if (code == nullptr) return;
    static const uint8_t als[] = "module lifted\n";
    uint8_t *bundle = nullptr;
    size_t blen = 0;
    uint32_t ni = 0, nb = 0;
    CHECK(pw_x86_lift_bundle(code, len, BASE, als, sizeof als - 1, &bundle, &blen, &ni, &nb) == PW_OK);
    if (bundle) {
        pw_verify_report_t rep;
        CHECK(pw_bundle_verify(bundle, blen, code, len, &rep) == PW_OK);
        CHECK(ni == corpus_insns);
        CHECK(rep.manifest.arch == PW_ARCH_X86_64);
        CHECK(rep.manifest.record_count == 4);       /* 2 indirect calls + 2 indirect jmps */
        CHECK(rep.manifest.overall_verdict == PW_VERDICT_UNKNOWN);
        printf("lift: %u instructions, %u blocks, %u records, %zu-byte bundle verifies\n",
               ni, nb, rep.manifest.record_count, blen);
        /* Fortran sees zero padding everywhere in the lifted bundle. */
        int32_t ibad = 0, ierr = 0;
        const int32_t km = PWF_MANIFEST, n192 = 192;
        pwval_(&km, bundle, &n192, &ibad, &ierr);
        CHECK(ibad == 0);
        int32_t istat[11];
        double dstat[9];
        const int32_t nr = (int32_t)rep.manifest.record_count;
        pwrst_(bundle + PW_MANIFEST_BYTES, &nr, istat, dstat);
        CHECK(istat[2] == 4 && istat[3] == 2 && istat[6] == 2 && istat[10] == 0);
    }
    free(bundle);
    free(code);
}

int main(int argc, char **argv) {
    if (argc < 2) { fputs("usage: test_xasm corpus.s\n", stderr); return 2; }
    test_known();
    test_corpus_roundtrip(argv[1]);
    test_random_roundtrip();
    test_fortran_layout();
    test_fortran_structs();
    test_fortran_numeric();
    test_lift(argv[1]);
    return TEST_DONE("test_xasm");
}
