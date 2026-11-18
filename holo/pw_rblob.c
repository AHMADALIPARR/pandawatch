/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Rust crate -> .rblob -> functors. C23. */
#include "pw_rblob.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_re.h"
#include "pw_sha256.h"
#include "pw_text.h"

typedef struct {
    const char *name;
    int size, align;
} rust_prim;

static const rust_prim rust_prims[] = {
    {"bool", 1, 1}, {"u8", 1, 1}, {"i8", 1, 1},
    {"u16", 2, 2}, {"i16", 2, 2},
    {"u32", 4, 4}, {"i32", 4, 4}, {"f32", 4, 4}, {"char", 4, 4},
    {"u64", 8, 8}, {"i64", 8, 8}, {"f64", 8, 8},
    {"usize", 8, 8}, {"isize", 8, 8},
    {"u128", 16, 16}, {"i128", 16, 16},
};

static long align_up(long v, long a) { return a > 1 ? (v + a - 1) & ~(a - 1) : v; }

static pw_re *re_cache(pw_re **slot, const char *pat, int flags) {
    if (*slot == nullptr) *slot = pw_re_compile(pat, flags);
    return *slot;
}

static pw_re *R_BLOCK, *R_LINE, *R_NAME, *R_VER, *R_TRAIT, *R_MACRO, *R_STRUCT, *R_FIELD, *R_IMPL, *R_FN;

static char *strip_comments(const char *src, size_t n, size_t *out_len) {
    size_t l1;
    char *a = pw_re_sub_empty(re_cache(&R_BLOCK, "/\\*.*?\\*/", PW_RE_S), src, n, &l1);
    char *b = pw_re_sub_empty(re_cache(&R_LINE, "//.*?$", PW_RE_M), a, l1, out_len);
    free(a);
    return b;
}

static void parse_cargo(const char *path, const char *crate_dir, char **name, char **ver) {
    size_t n;
    char *txt = pw_read_text(path, &n);
    if (txt == nullptr) pw_die("FileNotFoundError: [Errno %d] %s: '%s'", errno, strerror(errno), path);
    pw_rm m;
    *name = pw_re_search(re_cache(&R_NAME, "^\\s*name\\s*=\\s*\"([^\"]+)\"", PW_RE_M), txt, n, 0, &m)
                ? pw_rm_dup(&m, 1, txt) : pw_path_name(crate_dir);
    *ver = pw_re_search(re_cache(&R_VER, "^\\s*version\\s*=\\s*\"([^\"]+)\"", PW_RE_M), txt, n, 0, &m)
               ? pw_rm_dup(&m, 1, txt) : pw_dup("0.1.0");
    free(txt);
}

typedef struct {
    size_t start, end;
    char *trait_name, *owner;
} impl_span;

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static pj *sorted_unique(pw_strv *sv) {
    if (sv->n > 1) qsort(sv->v, sv->n, sizeof *sv->v, cmp_str);
    pj *a = pj_arr();
    for (size_t i = 0; i < sv->n; i++) {
        if (i && strcmp(sv->v[i], sv->v[i - 1]) == 0) continue;
        pj_push(a, pj_str(sv->v[i]));
    }
    return a;
}

static void parse_structs(const char *src, size_t n, pj *structs) {
    pw_re *re = re_cache(&R_STRUCT,
        "(?:#\\[repr\\(([^)]+)\\)\\]\\s*)?(?:pub\\s+)?struct\\s+([A-Za-z_]\\w*)(?:<([^>]+)>)?\\s*\\{([^}]*)\\}",
        PW_RE_S);
    pw_re *fre = re_cache(&R_FIELD, "^(?:pub(?:\\([^)]*\\))?\\s+)?([A-Za-z_]\\w*)\\s*:\\s*(.+)$", 0);
    pw_rm m;
    for (size_t p = 0; pw_re_next(re, src, n, &p, &m);) {
        char *repr_raw = pw_rm_dup(&m, 1, src);
        char *repr_kind = repr_raw ? pw_strip(repr_raw, strlen(repr_raw)) : pw_dup("Rust");
        free(repr_raw);
        char *sname = pw_rm_dup(&m, 2, src);
        pj *generics = pj_arr();
        if (pw_rm_set(&m, 3) && m.eo[3] > m.so[3]) {
            pw_strv g = pw_split_ch(src + m.so[3], (size_t)(m.eo[3] - m.so[3]), ',');
            for (size_t i = 0; i < g.n; i++) pj_push(generics, pj_strown(pw_strip(g.v[i], strlen(g.v[i]))));
            pw_strv_free(&g);
        }
        const bool packed = strstr(repr_kind, "packed") != nullptr;
        pj *fields = pj_arr();
        long cursor = 0, max_align = 1;
        pw_strv parts = pw_split_ch(src + m.so[4], (size_t)(m.eo[4] - m.so[4]), ',');
        for (size_t i = 0; i < parts.n; i++) {
            char *raw = pw_wsjoin(parts.v[i], strlen(parts.v[i]));
            pw_rm fm;
            if (!raw[0] || !pw_re_match_at(fre, raw, strlen(raw), 0, &fm)) { free(raw); continue; }
            char *fname = pw_rm_dup(&fm, 1, raw);
            char *fty0 = pw_rm_dup(&fm, 2, raw);
            char *fty = pw_strip(fty0, strlen(fty0));
            free(fty0);
            long fsz = 8, fal = 8;
            if (fty[0] != '&' && fty[0] != '*') {
                for (size_t k = 0; k < sizeof rust_prims / sizeof rust_prims[0]; k++) {
                    if (strcmp(fty, rust_prims[k].name) == 0) { fsz = rust_prims[k].size; fal = rust_prims[k].align; break; }
                }
            }
            const long eff = packed ? 1 : fal;
            if (eff > max_align) max_align = eff;
            const long off = align_up(cursor, eff);
            pj *f = pj_obj();
            pj_set(f, "name", pj_str(fname));
            pj_set(f, "ty", pj_str(fty));
            pj_set(f, "offset", pj_int(off));
            pj_set(f, "size", pj_int(fsz));
            pj_set(f, "align", pj_int(eff));
            pj_push(fields, f);
            cursor = off + fsz;
            free(fname);
            free(fty);
            free(raw);
        }
        pw_strv_free(&parts);
        const long tot = packed ? cursor : align_up(cursor, max_align);
        pj *st = pj_obj();
        pj_set(st, "name", pj_str(sname));
        pj_set(st, "repr_kind", pj_str(repr_kind));
        pj_set(st, "size", pj_int(tot));
        pj_set(st, "align", pj_int(max_align));
        pj_set(st, "generics", generics);
        pj_set(st, "fields", fields);
        pj_push(structs, st);
        free(sname);
        free(repr_kind);
    }
}

static void parse_fns(const char *src, size_t n, pj *functions) {
    pw_re *ire = re_cache(&R_IMPL,
        "\\bimpl(?:<[^>]+>)?\\s+(?:([A-Za-z_]\\w*)\\s+for\\s+)?([A-Za-z_]\\w*)(?:<[^>]+>)?\\s*\\{", PW_RE_M);
    impl_span *spans = nullptr;
    size_t nspans = 0;
    pw_rm m;
    for (size_t p = 0; pw_re_next(ire, src, n, &p, &m);) {
        const size_t start = (size_t)m.eo[0] - 1;
        size_t end = start;
        long depth = 0;
        for (size_t i = start; i < n; i++) {
            if (src[i] == '{') depth++;
            else if (src[i] == '}') {
                depth--;
                if (depth == 0) { end = i; break; }
            }
        }
        impl_span *ns = realloc(spans, sizeof *spans * (nspans + 1));
        if (ns == nullptr) abort();
        spans = ns;
        spans[nspans++] = (impl_span){ start, end, pw_rm_dup(&m, 1, src), pw_rm_dup(&m, 2, src) };
    }
    pw_re *fre = re_cache(&R_FN,
        "\\b(?:pub\\s+)?fn\\s+([A-Za-z_]\\w*)(?:<[^>]+>)?\\s*\\(([^)]*)\\)\\s*(?:->\\s*([^{;]+))?", PW_RE_M);
    for (size_t p = 0; pw_re_next(fre, src, n, &p, &m);) {
        const size_t fpos = (size_t)m.so[0];
        const char *owner = nullptr, *trait_name = nullptr;
        for (size_t s = 0; s < nspans; s++) {
            if (spans[s].start <= fpos && fpos <= spans[s].end) {
                trait_name = spans[s].trait_name;
                owner = spans[s].owner;
                break;
            }
        }
        pj *params = pj_arr();
        pw_strv ps = pw_split_ch(src + m.so[2], (size_t)(m.eo[2] - m.so[2]), ',');
        for (size_t i = 0; i < ps.n; i++) {
            char *pr = pw_strip(ps.v[i], strlen(ps.v[i]));
            if (pr[0]) {
                const char *colon = strchr(pr, ':');
                if (strstr(pr, "self") && colon == nullptr) {
                    pj *t = pj_arr();
                    pj_push(t, pj_str("self"));
                    pj_push(t, pj_str(owner ? owner : "Self"));
                    pj_push(params, t);
                } else if (colon) {
                    char *pn = pw_strip(pr, (size_t)(colon - pr));
                    char *pt = pw_strip(colon + 1, strlen(colon + 1));
                    pj *t = pj_arr();
                    pj_push(t, pj_str(pn));
                    pj_push(t, pj_str(pt));
                    pj_push(params, t);
                    free(pn);
                    free(pt);
                }
            }
            free(pr);
        }
        pw_strv_free(&ps);
        char *ret = pw_rm_set(&m, 3) ? pw_strip(src + m.so[3], (size_t)(m.eo[3] - m.so[3])) : pw_dup("()");
        pj *fn = pj_obj();
        char *fname = pw_rm_dup(&m, 1, src);
        pj_set(fn, "name", pj_str(fname));
        pj_set(fn, "params", params);
        pj_set(fn, "ret_ty", pj_str(ret));
        pj_set(fn, "owner_type", pj_str(owner));
        pj_set(fn, "trait_name", pj_str(trait_name));
        pj_push(functions, fn);
        free(fname);
        free(ret);
    }
    for (size_t s = 0; s < nspans; s++) { free(spans[s].trait_name); free(spans[s].owner); }
    free(spans);
}

pj *pw_rblob_parse_crate(const char *crate_path) {
    char *name, *ver;
    pw_strv files = {0};
    if (pw_path_isdir(crate_path)) {
        char *cargo = pw_path_join(crate_path, "Cargo.toml");
        if (pw_path_exists(cargo)) parse_cargo(cargo, crate_path, &name, &ver);
        else { name = pw_path_name(crate_path); ver = pw_dup("0.1.0"); }
        free(cargo);
        files = pw_rglob_suffix(crate_path, ".rs");
    } else {
        name = pw_path_stem(crate_path);
        ver = pw_dup("0.1.0");
        pw_strv_push(&files, pw_path_norm(crate_path));
    }
    pj *structs = pj_arr(), *functions = pj_arr(), *fnames = pj_arr();
    pw_strv traits = {0}, macros = {0};
    pw_re *tre = re_cache(&R_TRAIT, "\\b(?:pub\\s+)?trait\\s+([A-Za-z_]\\w*)", 0);
    pw_re *mre = re_cache(&R_MACRO, "\\bmacro_rules!\\s+([A-Za-z_]\\w*)", 0);
    for (size_t i = 0; i < files.n; i++) {
        size_t rn;
        char *raw = pw_read_text(files.v[i], &rn);
        if (raw == nullptr) pw_die("FileNotFoundError: [Errno %d] %s: '%s'", errno, strerror(errno), files.v[i]);
        size_t n;
        char *src = strip_comments(raw, rn, &n);
        free(raw);
        pw_rm m;
        for (size_t p = 0; pw_re_next(tre, src, n, &p, &m);) pw_strv_push(&traits, pw_rm_dup(&m, 1, src));
        for (size_t p = 0; pw_re_next(mre, src, n, &p, &m);) pw_strv_push(&macros, pw_rm_dup(&m, 1, src));
        parse_structs(src, n, structs);
        parse_fns(src, n, functions);
        free(src);
    }
    for (size_t i = 0; i < files.n; i++) {
        char *b = pw_path_name(files.v[i]);
        pj_push(fnames, pj_str(b));
        free(b);
    }
    pj *ir = pj_obj();
    pj_set(ir, "crate", pj_str(name));
    pj_set(ir, "version", pj_str(ver));
    pj_set(ir, "files", fnames);
    pj_set(ir, "structs", structs);
    pj_set(ir, "functions", functions);
    pj_set(ir, "traits", sorted_unique(&traits));
    pj_set(ir, "macros", sorted_unique(&macros));
    pw_strv_free(&traits);
    pw_strv_free(&macros);
    pw_strv_free(&files);
    free(name);
    free(ver);
    return ir;
}

uint8_t *pw_rblob_build(const pj *crate_ir, size_t *len, char hex[65]) {
    size_t pl;
    char *payload = pj_dump(crate_ir, -1, true, &pl);
    uint8_t dig[32];
    pw_sha256(payload, pl, dig);
    pw_hex32(dig, hex);
    uint8_t *blob = malloc(PW_RBLOB_HEADER + pl);
    if (blob == nullptr) abort();
    memcpy(blob, PW_RBLOB_MAGIC, 6);
    memcpy(blob + 6, dig, 32);
    blob[38] = (uint8_t)pl;
    blob[39] = (uint8_t)(pl >> 8);
    blob[40] = (uint8_t)(pl >> 16);
    blob[41] = (uint8_t)(pl >> 24);
    memcpy(blob + PW_RBLOB_HEADER, payload, pl);
    free(payload);
    *len = PW_RBLOB_HEADER + pl;
    return blob;
}

pj *pw_rblob_verify(const uint8_t *blob, size_t len, char *err, size_t errcap) {
    if (len < PW_RBLOB_HEADER || memcmp(blob, PW_RBLOB_MAGIC, 6) != 0) {
        snprintf(err, errcap, "ValueError: Invalid .rblob magic or truncated header");
        return nullptr;
    }
    const uint32_t plen = (uint32_t)blob[38] | (uint32_t)blob[39] << 8 | (uint32_t)blob[40] << 16 | (uint32_t)blob[41] << 24;
    const size_t actual = len - PW_RBLOB_HEADER;
    if (actual != plen) {
        snprintf(err, errcap, "ValueError: Blob length mismatch: header=%u, actual=%zu", plen, actual);
        return nullptr;
    }
    uint8_t dig[32];
    pw_sha256(blob + PW_RBLOB_HEADER, actual, dig);
    if (memcmp(dig, blob + 6, 32) != 0) {
        snprintf(err, errcap, "ValueError: Blob SHA-256 verification failed: corrupted or tampered binary blob");
        return nullptr;
    }
    if (!pw_utf8_valid(blob + PW_RBLOB_HEADER, actual)) {
        snprintf(err, errcap, "UnicodeDecodeError: 'utf-8' codec can't decode the .rblob payload");
        return nullptr;
    }
    char jerr[256];
    pj *ir = pj_parse((const char *)blob + PW_RBLOB_HEADER, actual, jerr, sizeof jerr);
    if (ir == nullptr) {
        snprintf(err, errcap, "json.decoder.JSONDecodeError: %s", jerr);
        return nullptr;
    }
    char hex[65];
    pw_hex32(dig, hex);
    pj *r = pj_obj();
    pj_set(r, "verified", pj_bool(true));
    pj_set(r, "sha256", pj_str(hex));
    pj_set(r, "blob_bytes", pj_int((int64_t)len));
    pj_set(r, "crate_ir", ir);
    return r;
}

static const pj *need(const pj *o, const char *key, char *err, size_t errcap) {
    const pj *v = pj_get(o, key);
    if (v == nullptr && err[0] == 0) snprintf(err, errcap, "KeyError: '%s'", key);
    return v;
}

static pj *dom_of(const pj *params) {
    pj *d = pj_arr();
    for (size_t i = 0; params && i < params->n; i++) {
        const pj *p = params->v[i];
        pj_push(d, (p->t == PJ_ARR && p->n > 1) ? pj_copy(p->v[1]) : pj_null());
    }
    return d;
}

static char *int_text(const pj *v) {
    if (v && v->t == PJ_STR) return pw_dup(v->s);
    char *s = pj_dump(v ? v : &(pj){ .t = PJ_NULL }, -1, false, nullptr);
    return s;
}

pj *pw_rblob_disassemble(const uint8_t *blob, size_t len, char *err, size_t errcap) {
    err[0] = 0;
    pj *v = pw_rblob_verify(blob, len, err, errcap);
    if (v == nullptr) return nullptr;
    const pj *ir = pj_get(v, "crate_ir");
    const pj *crate = need(ir, "crate", err, errcap);
    const pj *fns = need(ir, "functions", err, errcap);
    const pj *structs = need(ir, "structs", err, errcap);
    if (err[0]) { pj_free(v); return nullptr; }
    const char *crate_name = pj_as_str(crate);

    pj *functors = pj_arr();
    for (size_t s = 0; structs && s < structs->n; s++) {
        const pj *st = structs->v[s];
        const char *sname = pj_as_str(pj_get(st, "name"));
        pj *f_obj = pj_obj();
        pj_set(f_obj, "source_type", pj_copy(pj_get(st, "name")));
        pj_set(f_obj, "generics", pj_copy(pj_get(st, "generics")));
        pj_set(f_obj, "repr", pj_copy(pj_get(st, "repr_kind")));
        pj_set(f_obj, "abi_bytes", pj_copy(pj_get(st, "size")));
        pj_set(f_obj, "abi_align", pj_copy(pj_get(st, "align")));
        pj_set(f_obj, "fields", pj_copy(pj_get(st, "fields")));
        pj *f_mor = pj_arr();
        for (size_t i = 0; fns && i < fns->n; i++) {
            const pj *fn = fns->v[i];
            const pj *ow = pj_get(fn, "owner_type");
            if (!pj_truthy(ow) || ow->t != PJ_STR || strcmp(ow->s, sname) != 0) continue;
            pj *mo = pj_obj();
            pj_set(mo, "morphism", pj_copy(pj_get(fn, "name")));
            pj_set(mo, "trait", pj_copy(pj_get(fn, "trait_name")));
            pj_set(mo, "dom", dom_of(pj_get(fn, "params")));
            pj_set(mo, "cod", pj_copy(pj_get(fn, "ret_ty")));
            pj_push(f_mor, mo);
        }
        char *sz = int_text(pj_get(st, "size")), *al = int_text(pj_get(st, "align"));
        pj *laws = pj_arr();
        pj_push(laws, pj_strown(pw_fmt("id_%s : F.map id = id", sname)));
        pj_push(laws, pj_strown(pw_fmt("comp_%s : F.map (g \u2218 f) = F.map g \u2218 F.map f", sname)));
        pj_push(laws, pj_strown(pw_fmt("abi_preserve_%s : sizeof(%s) = %s \u2227 align(%s) = %s", sname, sname, sz, sname, al)));
        char *lean = pw_fmt("def F_%s : Type \u2192 Type := fun _ => %s -- %zu morphisms, %sB @ align %s",
                            sname, sname, f_mor->n, sz, al);
        char *fname = pw_fmt("Functor_%s", sname);
        pj *F = pj_obj();
        pj_set(F, "name", pj_str(fname));
        pj_set(F, "source_crate", pj_copy(crate));
        pj_set(F, "domain_cat", pj_str("RustType"));
        pj_set(F, "codomain_cat", pj_str("HoloABI"));
        pj_set(F, "f_obj", f_obj);
        pj_set(F, "f_mor", f_mor);
        pj_set(F, "laws", laws);
        pj_set(F, "lean_signature", pj_str(lean));
        pj_push(functors, F);
        free(sz);
        free(al);
        free(lean);
        free(fname);
    }
    pj *free_mor = pj_arr();
    for (size_t i = 0; fns && i < fns->n; i++) {
        const pj *fn = fns->v[i];
        if (pj_truthy(pj_get(fn, "owner_type"))) continue;
        pj *mo = pj_obj();
        pj_set(mo, "morphism", pj_copy(pj_get(fn, "name")));
        pj_set(mo, "dom", dom_of(pj_get(fn, "params")));
        pj_set(mo, "cod", pj_copy(pj_get(fn, "ret_ty")));
        pj_push(free_mor, mo);
    }
    if (free_mor->n) {
        pj *f_obj = pj_obj();
        pj_set(f_obj, "crate", pj_copy(crate));
        pj_set(f_obj, "version", pj_copy(pj_get(ir, "version")));
        pj_set(f_obj, "traits", pj_copy(pj_get(ir, "traits")));
        pj_set(f_obj, "macros", pj_copy(pj_get(ir, "macros")));
        pj *laws = pj_arr();
        pj_push(laws, pj_str("module_id : F_mod.map id = id"));
        char *fname = pw_fmt("Functor_%s_Module", crate_name);
        char *lean = pw_fmt("def F_%s_mod : RustModule \u2192 HoloCFG", crate_name);
        pj *F = pj_obj();
        pj_set(F, "name", pj_str(fname));
        pj_set(F, "source_crate", pj_copy(crate));
        pj_set(F, "domain_cat", pj_str("RustModule"));
        pj_set(F, "codomain_cat", pj_str("HoloCFG"));
        pj_set(F, "f_obj", f_obj);
        pj_set(F, "f_mor", free_mor);
        pj_set(F, "laws", laws);
        pj_set(F, "lean_signature", pj_str(lean));
        pj_push(functors, F);
        free(fname);
        free(lean);
    } else {
        pj_free(free_mor);
    }
    pj *r = pj_obj();
    pj_set(r, "verified", pj_bool(true));
    pj_set(r, "sha256", pj_copy(pj_get(v, "sha256")));
    pj_set(r, "crate", pj_copy(crate));
    pj_set(r, "version", pj_copy(pj_get(ir, "version")));
    pj_set(r, "functor_count", pj_int((int64_t)functors->n));
    pj_set(r, "functors", functors);
    pj_free(v);
    return r;
}
