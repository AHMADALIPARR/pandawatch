/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* BSM ingestion pipeline and the .holo.wasm packer / inspector.
 *
 * Module layout: magic + version 1, type section (() -> i32), function
 * section (4 x type 0), memory section, export section (memory,
 * holo_version, holo_layer_count, holo_manifest_ptr, holo_manifest_len),
 * code section (i32.const bodies), data section (the manifest JSON at
 * linear-memory offset 0x1000), then custom sections holo.manifest,
 * holo.types, holo.layouts, holo.cfg, holo.symbols and, when Rust inputs
 * were packed, holo.functors. Every layer is compact JSON; the manifest
 * records each layer's size and SHA-256 and a root SHA-256 over the layer
 * digests in sorted layer-name order. C23. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_bsm.h"
#include "pw_rblob.h"
#include "pw_sha256.h"
#include "pw_sqlite.h"
#include "pw_text.h"

/* ---- ingestion ---- */

static void rust_input(pw_holo_ir *ir, const char *path, const char *fname, bool is_blob) {
    uint8_t *blob;
    size_t len;
    if (is_blob) {
        blob = pw_slurp(path, &len);
        if (blob == nullptr) pw_die("FileNotFoundError: [Errno %d] %s: '%s'", errno, strerror(errno), path);
    } else {
        pj *crate = pw_rblob_parse_crate(path);
        char hex[65];
        blob = pw_rblob_build(crate, &len, hex);
        pj_free(crate);
    }
    char err[512];
    pj *dis = pw_rblob_disassemble(blob, len, err, sizeof err);
    free(blob);
    if (dis == nullptr) pw_die("%s", err);
    const pj *functors = pj_get(dis, "functors");
    for (size_t i = 0; i < functors->n; i++) {
        const pj *F = functors->v[i];
        const pj *obj = pj_get(F, "f_obj");
        if (pj_get(obj, "source_type")) {
            pj *fields = pj_arr();
            int64_t used = 0;
            const pj *fl = pj_get(obj, "fields");
            for (size_t k = 0; fl && k < fl->n; k++) {
                const pj *f = fl->v[k];
                pj *fo = pj_obj();
                pj_set(fo, "name", pj_copy(pj_get(f, "name")));
                pj_set(fo, "type_name", pj_copy(pj_get(f, "ty")));
                pj_set(fo, "offset", pj_copy(pj_get(f, "offset")));
                pj_set(fo, "size", pj_copy(pj_get(f, "size")));
                pj_set(fo, "align", pj_copy(pj_get(f, "align")));
                pj_set(fo, "kind", pj_str("primitive"));
                pj_set(fo, "notes", pj_str(""));
                pj_push(fields, fo);
                used += pj_as_int(pj_get(f, "size"));
            }
            const int64_t total = pj_as_int(pj_get(obj, "abi_bytes"));
            pj *meta = pj_obj();
            pj_set(meta, "repr", pj_copy(pj_get(obj, "repr")));
            pj_set(meta, "functor", pj_copy(pj_get(F, "name")));
            pj *r = pj_obj();
            pj_set(r, "name", pj_copy(pj_get(obj, "source_type")));
            pj_set(r, "source_kind", pj_str("rust"));
            pj_set(r, "source_file", pj_str(fname));
            pj_set(r, "kind", pj_str("struct"));
            pj_set(r, "total_size", pj_int(total));
            pj_set(r, "align", pj_copy(pj_get(obj, "abi_align")));
            pj_set(r, "padding_bytes", pj_int(total > used ? total - used : 0));
            pj_set(r, "fields", fields);
            pj_set(r, "metadata", meta);
            pj_push(ir->records, r);
            pj *s = pj_obj();
            pj_set(s, "name", pj_copy(pj_get(obj, "source_type")));
            pj_set(s, "source_kind", pj_str("rust"));
            pj_set(s, "source_file", pj_str(fname));
            pj_set(s, "sym_type", pj_str("RECORD"));
            pj_set(s, "binding", pj_str("GLOBAL"));
            pj_set(s, "address", pj_int(0));
            pj_set(s, "size", pj_int(total));
            pj_set(s, "section", pj_str(""));
            pj_push(ir->symbols, s);
        }
        const pj *mor = pj_get(F, "f_mor");
        for (size_t k = 0; mor && k < mor->n; k++) {
            pj *s = pj_obj();
            pj_set(s, "name", pj_copy(pj_get(mor->v[k], "morphism")));
            pj_set(s, "source_kind", pj_str("rust"));
            pj_set(s, "source_file", pj_str(fname));
            pj_set(s, "sym_type", pj_str("FUNC"));
            pj_set(s, "binding", pj_str("GLOBAL"));
            pj_set(s, "address", pj_int(0));
            pj_set(s, "size", pj_int(0));
            pj_set(s, "section", pj_str(""));
            pj_push(ir->symbols, s);
        }
        pj_push(ir->functors, pj_copy(F));
    }
    pj_free(dis);
}

static void add_source(pw_holo_ir *ir, const char *fname, const char *kind) {
    pj *s = pj_obj();
    pj_set(s, "file", pj_str(fname));
    pj_set(s, "kind", pj_str(kind));
    pj_push(ir->sources, s);
}

static bool suffix_in(const char *suf, const char *const *set, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(suf, set[i]) == 0) return true;
    }
    return false;
}
#define SUF(s, ...) suffix_in((s), (const char *const[]){ __VA_ARGS__ }, \
                              sizeof((const char *const[]){ __VA_ARGS__ }) / sizeof(const char *))

void pw_bsm_ingest(pw_holo_ir *ir, const char *const *paths, size_t n, const char *abi) {
    for (size_t i = 0; i < n; i++) {
        const char *p = paths[i];
        char *shown = pw_path_norm(p);
        if (!pw_path_exists(p)) pw_die("FileNotFoundError: Input not found: %s", shown);
        char *name = pw_path_name(p);
        char *s0 = pw_path_suffix(p);
        char *suf = pw_lower(s0);
        free(s0);
        if (pw_path_isdir(p) || SUF(suf, ".rs", ".rblob")) {
            rust_input(ir, p, name, strcmp(suf, ".rblob") == 0);
            add_source(ir, name, "rust");
        } else {
            size_t len;
            uint8_t *raw = pw_slurp(p, &len);
            if (raw == nullptr) pw_die("OSError: [Errno %d] %s: '%s'", errno, strerror(errno), shown);
            const bool elf = len >= 4 && memcmp(raw, "\x7f" "ELF", 4) == 0;
            const bool sqlite_magic = len >= 15 && memcmp(raw, "SQLite format 3", 15) == 0;
            if (elf || SUF(suf, ".elf", ".o", ".so")) {
                free(raw);
                pj *hdr = pw_bsm_parse_elf(p, name, ir->symbols, ir->cfgs);
                pj_push(ir->elf_headers, hdr);
                add_source(ir, name, "elf");
            } else if (SUF(suf, ".c", ".h", ".cpp", ".hpp")) {
                size_t tl;
                char *t = pw_decode_text(raw, len, &tl);
                free(raw);
                pw_bsm_parse_c(t, tl, name, abi, ir->records, ir->symbols);
                free(t);
                add_source(ir, name, "c");
            } else if (SUF(suf, ".cbl", ".cob", ".cpy")) {
                size_t tl;
                char *t = pw_decode_text(raw, len, &tl);
                free(raw);
                pw_bsm_parse_cobol(t, tl, name, ir->records, ir->symbols);
                free(t);
                add_source(ir, name, "cobol");
            } else if (SUF(suf, ".db", ".sqlite", ".sqlite3", ".sql") || sqlite_magic) {
                free(raw);
                pw_sqlite_ingest(p, name, ir->records, ir->symbols);
                add_source(ir, name, "sqlite");
            } else if (SUF(suf, ".s", ".asm")) {
                size_t tl;
                char *t = pw_decode_text(raw, len, &tl);
                free(raw);
                pw_bsm_parse_asm(t, tl, name, "asm", ir->cfgs, ir->symbols);
                free(t);
                add_source(ir, name, "asm");
            } else {
                pw_die("ValueError: Unsupported legacy input type: %s", shown);
            }
        }
        free(shown);
        free(name);
        free(suf);
    }
    pw_bsm_analyze(ir);
}

/* ---- wasm encoding ---- */

static void uleb(pw_buf *b, uint64_t v) {
    do {
        uint8_t byte = v & 0x7F;
        v >>= 7;
        if (v) byte |= 0x80;
        pw_buf_putc(b, byte);
    } while (v);
}

static void wstr(pw_buf *b, const char *s, size_t n) {
    uleb(b, n);
    pw_buf_put(b, s, n);
}

static void section(pw_buf *out, uint8_t id, const pw_buf *payload) {
    pw_buf_putc(out, id);
    uleb(out, payload->n);
    pw_buf_put(out, payload->p, payload->n);
}

static void i32_const(pw_buf *b, int64_t v) {
    pw_buf_putc(b, 0x41);
    bool more = true;
    while (more) {
        uint8_t byte = v & 0x7F;
        v >>= 7;
        if ((v == 0 && !(byte & 0x40)) || (v == -1 && (byte & 0x40))) more = false;
        else byte |= 0x80;
        pw_buf_putc(b, byte);
    }
    pw_buf_putc(b, 0x0B);
}

typedef struct {
    const char *name;
    char *bytes;
    size_t len;
} layer;

uint8_t *pw_bsm_pack(const pw_holo_ir *ir, size_t *out_len, pj **manifest_out) {
    layer layers[5];
    size_t nl = 0;
    layers[nl].name = "holo.types";
    layers[nl].bytes = pj_dump(ir->records, -1, false, &layers[nl].len);
    nl++;
    pj *lay = pj_arr();
    for (size_t i = 0; i < ir->records->n; i++) {
        const pj *r = ir->records->v[i];
        pj *o = pj_obj();
        pj_set(o, "name", pj_copy(pj_get(r, "name")));
        pj_set(o, "source", pj_copy(pj_get(r, "source_kind")));
        pj_set(o, "size", pj_copy(pj_get(r, "total_size")));
        pj_set(o, "align", pj_copy(pj_get(r, "align")));
        pj_set(o, "padding", pj_copy(pj_get(r, "padding_bytes")));
        pj_set(o, "fields", pj_copy(pj_get(r, "fields")));
        pj_push(lay, o);
    }
    layers[nl].name = "holo.layouts";
    layers[nl].bytes = pj_dump(lay, -1, false, &layers[nl].len);
    nl++;
    pj_free(lay);
    layers[nl].name = "holo.cfg";
    layers[nl].bytes = pj_dump(ir->cfgs, -1, false, &layers[nl].len);
    nl++;
    pj *sy = pj_obj();
    pj_set(sy, "elf_headers", pj_copy(ir->elf_headers));
    pj_set(sy, "symbols", pj_copy(ir->symbols));
    pj_set(sy, "cross_links", pj_copy(ir->cross_links));
    layers[nl].name = "holo.symbols";
    layers[nl].bytes = pj_dump(sy, -1, false, &layers[nl].len);
    nl++;
    pj_free(sy);
    if (ir->functors->n) {
        layers[nl].name = "holo.functors";
        layers[nl].bytes = pj_dump(ir->functors, -1, false, &layers[nl].len);
        nl++;
    }

    pj *index = pj_obj();
    char hexes[5][65];
    for (size_t i = 0; i < nl; i++) {
        uint8_t dig[32];
        pw_sha256(layers[i].bytes, layers[i].len, dig);
        pw_hex32(dig, hexes[i]);
        pj *e = pj_obj();
        pj_set(e, "bytes", pj_int((int64_t)layers[i].len));
        pj_set(e, "sha256", pj_str(hexes[i]));
        pj_set(index, layers[i].name, e);
    }
    /* root = sha256("".join(sha for name in sorted(names))) */
    size_t order[5];
    for (size_t i = 0; i < nl; i++) order[i] = i;
    for (size_t i = 1; i < nl; i++) {
        for (size_t j = i; j > 0 && strcmp(layers[order[j - 1]].name, layers[order[j]].name) > 0; j--) {
            const size_t t = order[j]; order[j] = order[j - 1]; order[j - 1] = t;
        }
    }
    pw_sha256_ctx ctx;
    pw_sha256_init(&ctx);
    for (size_t i = 0; i < nl; i++) pw_sha256_update(&ctx, hexes[order[i]], 64);
    uint8_t root[32];
    pw_sha256_final(&ctx, root);
    char roothex[65];
    pw_hex32(root, roothex);

    pj *man = pj_obj();
    pj_set(man, "format", pj_str("wasm-holo/1.0"));
    pj_set(man, "root_sha256", pj_str(roothex));
    pj_set(man, "sources", pj_copy(ir->sources));
    pj *stats = pj_obj();
    pj_set(stats, "records", pj_int((int64_t)ir->records->n));
    pj_set(stats, "cfgs", pj_int((int64_t)ir->cfgs->n));
    pj_set(stats, "symbols", pj_int((int64_t)ir->symbols->n));
    pj_set(stats, "cross_links", pj_int((int64_t)ir->cross_links->n));
    if (ir->functors->n) pj_set(stats, "functors", pj_int((int64_t)ir->functors->n));
    pj_set(man, "stats", stats);
    pj_set(man, "layers", index);
    size_t mlen;
    char *mbytes = pj_dump(man, -1, false, &mlen);
    const int64_t moff = 0x1000;

    pw_buf out = {0}, pl = {0};
    pw_buf_put(&out, "\0asm\1\0\0\0", 8);
    /* type */
    uleb(&pl, 1);
    pw_buf_put(&pl, "\x60\x00\x01\x7F", 4);
    section(&out, 1, &pl);
    pl.n = 0;
    /* function */
    uleb(&pl, 4);
    pw_buf_put(&pl, "\0\0\0\0", 4);
    section(&out, 3, &pl);
    pl.n = 0;
    /* memory */
    const uint64_t need = (uint64_t)moff + mlen + 64;
    uint64_t pages = (need + 65535) / 65536;
    if (pages < 1) pages = 1;
    uleb(&pl, 1);
    pw_buf_putc(&pl, 0);
    uleb(&pl, pages);
    section(&out, 5, &pl);
    pl.n = 0;
    /* exports */
    uleb(&pl, 5);
    wstr(&pl, "memory", 6); pw_buf_put(&pl, "\x02\x00", 2);
    wstr(&pl, "holo_version", 12); pw_buf_put(&pl, "\x00\x00", 2);
    wstr(&pl, "holo_layer_count", 16); pw_buf_put(&pl, "\x00\x01", 2);
    wstr(&pl, "holo_manifest_ptr", 17); pw_buf_put(&pl, "\x00\x02", 2);
    wstr(&pl, "holo_manifest_len", 17); pw_buf_put(&pl, "\x00\x03", 2);
    section(&out, 7, &pl);
    pl.n = 0;
    /* code: each body = locals(0) + i32.const v + end, prefixed by its size */
    const int64_t vals[4] = { 1, (int64_t)nl + 1, moff, (int64_t)mlen };
    uleb(&pl, 4);
    for (int i = 0; i < 4; i++) {
        pw_buf body = {0};
        pw_buf_putc(&body, 0);
        i32_const(&body, vals[i]);
        uleb(&pl, body.n);
        pw_buf_put(&pl, body.p, body.n);
        free(body.p);
    }
    section(&out, 10, &pl);
    pl.n = 0;
    /* data: active segment, memory 0, offset 0x1000 */
    uleb(&pl, 1);
    pw_buf_putc(&pl, 0);
    i32_const(&pl, moff);
    uleb(&pl, mlen);
    pw_buf_put(&pl, mbytes, mlen);
    section(&out, 11, &pl);
    pl.n = 0;
    /* custom sections */
    wstr(&pl, "holo.manifest", 13);
    pw_buf_put(&pl, mbytes, mlen);
    section(&out, 0, &pl);
    pl.n = 0;
    for (size_t i = 0; i < nl; i++) {
        wstr(&pl, layers[i].name, strlen(layers[i].name));
        pw_buf_put(&pl, layers[i].bytes, layers[i].len);
        section(&out, 0, &pl);
        pl.n = 0;
        free(layers[i].bytes);
    }
    free(pl.p);
    free(mbytes);
    *manifest_out = man;
    return (uint8_t *)pw_buf_take(&out, out_len);
}

/* ---- inspector ---- */

static bool rd_uleb(const uint8_t *b, size_t n, size_t *pos, uint64_t *out) {
    uint64_t r = 0;
    unsigned shift = 0;
    for (;;) {
        if (*pos >= n) return false;
        const uint8_t c = b[(*pos)++];
        if (shift < 64) r |= (uint64_t)(c & 0x7F) << shift;
        if (!(c & 0x80)) { *out = r; return true; }
        shift += 7;
    }
}

pj *pw_bsm_inspect(const uint8_t *w, size_t n, char *err, size_t errcap) {
    if (n < 8 || memcmp(w, "\0asm\1\0\0\0", 8) != 0) {
        snprintf(err, errcap, "ValueError: Invalid WebAssembly 1.0 magic/version header");
        return nullptr;
    }
    size_t pos = 8;
    pj *std_secs = pj_arr();
    pj *holo = pj_obj();   /* name -> {bytes, sha256, data} */
    while (pos < n) {
        const uint8_t id = w[pos++];
        uint64_t slen;
        if (!rd_uleb(w, n, &pos, &slen)) {
            snprintf(err, errcap, "IndexError: index out of range");
            pj_free(std_secs); pj_free(holo);
            return nullptr;
        }
        const size_t avail = pos < n ? n - pos : 0;
        const size_t plen = slen < avail ? (size_t)slen : avail;
        const uint8_t *pay = w + pos;
        pos = slen > avail ? n : pos + (size_t)slen;
        if (id == 0) {
            size_t np = 0;
            uint64_t nlen;
            if (!rd_uleb(pay, plen, &np, &nlen)) {
                snprintf(err, errcap, "IndexError: index out of range");
                pj_free(std_secs); pj_free(holo);
                return nullptr;
            }
            const size_t nav = np < plen ? plen - np : 0;
            const size_t nl = nlen < nav ? (size_t)nlen : nav;
            char *name = pw_decode_utf8(pay + np, nl, nullptr);
            const size_t bstart = np + nlen < plen ? np + (size_t)nlen : plen;
            const uint8_t *body = pay + bstart;
            const size_t blen = plen - bstart;
            if (pw_startswith(name, "holo.")) {
                if (!pw_utf8_valid(body, blen)) {
                    snprintf(err, errcap, "UnicodeDecodeError: 'utf-8' codec can't decode section %s", name);
                    free(name); pj_free(std_secs); pj_free(holo);
                    return nullptr;
                }
                char jerr[256];
                pj *data = pj_parse((const char *)body, blen, jerr, sizeof jerr);
                if (data == nullptr) {
                    snprintf(err, errcap, "json.decoder.JSONDecodeError: %s", jerr);
                    free(name); pj_free(std_secs); pj_free(holo);
                    return nullptr;
                }
                uint8_t dig[32];
                char hex[65];
                pw_sha256(body, blen, dig);
                pw_hex32(dig, hex);
                pj *e = pj_obj();
                pj_set(e, "bytes", pj_int((int64_t)blen));
                pj_set(e, "sha256", pj_str(hex));
                pj_set(e, "data", data);
                pj_set(holo, name, e);
            }
            free(name);
        } else {
            pj *s = pj_obj();
            pj_set(s, "id", pj_int(id));
            pj_set(s, "bytes", pj_uint(slen));
            pj_push(std_secs, s);
        }
    }
    const pj *me = pj_get(holo, "holo.manifest");
    pj *manifest = me ? pj_copy(pj_get(me, "data")) : pj_obj();
    bool verified = true;
    const pj *ml = manifest->t == PJ_OBJ ? pj_get(manifest, "layers") : nullptr;
    for (size_t i = 0; ml && ml->t == PJ_OBJ && i < ml->n; i++) {
        const pj *have = pj_get(holo, ml->k[i]);
        const pj *want = pj_get(ml->v[i], "sha256");
        const pj *got = have ? pj_get(have, "sha256") : nullptr;
        if (!have || !want || want->t != PJ_STR || strcmp(got->s, want->s) != 0) verified = false;
    }
    pj *layers = pj_obj();
    for (size_t i = 0; i < holo->n; i++) {
        if (strcmp(holo->k[i], "holo.manifest") == 0) continue;
        pj_set(layers, holo->k[i], pj_copy(pj_get(holo->v[i], "data")));
    }
    pj *r = pj_obj();
    pj_set(r, "valid_wasm", pj_bool(true));
    pj_set(r, "total_bytes", pj_int((int64_t)n));
    pj_set(r, "standard_sections", std_secs);
    pj_set(r, "integrity_verified", pj_bool(verified));
    pj_set(r, "manifest", manifest);
    pj_set(r, "layers", layers);
    pj_free(holo);
    return r;
}
