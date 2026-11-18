/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* BSM frontends: C, COBOL, assembly; cross-source linking. C23. */
#include "pw_bsm.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_re.h"
#include "pw_text.h"

void pw_holo_ir_init(pw_holo_ir *ir) {
    ir->sources = pj_arr();
    ir->records = pj_arr();
    ir->cfgs = pj_arr();
    ir->symbols = pj_arr();
    ir->elf_headers = pj_arr();
    ir->cross_links = pj_arr();
    ir->functors = pj_arr();
}

void pw_holo_ir_free(pw_holo_ir *ir) {
    pj_free(ir->sources);
    pj_free(ir->records);
    pj_free(ir->cfgs);
    pj_free(ir->symbols);
    pj_free(ir->elf_headers);
    pj_free(ir->cross_links);
    pj_free(ir->functors);
}

/* ---- IR constructors (dataclass field order) ---- */

static pj *mk_field(const char *name, const char *type_name, int64_t off, int64_t size, int64_t align,
                    const char *kind, const char *notes) {
    pj *f = pj_obj();
    pj_set(f, "name", pj_str(name));
    pj_set(f, "type_name", pj_str(type_name));
    pj_set(f, "offset", pj_int(off));
    pj_set(f, "size", pj_int(size));
    pj_set(f, "align", pj_int(align));
    pj_set(f, "kind", pj_str(kind));
    pj_set(f, "notes", pj_str(notes));
    return f;
}

static pj *mk_record(const char *name, const char *source_kind, const char *fname, const char *kind,
                     int64_t total, int64_t align, int64_t padding, pj *fields, pj *meta) {
    pj *r = pj_obj();
    pj_set(r, "name", pj_str(name));
    pj_set(r, "source_kind", pj_str(source_kind));
    pj_set(r, "source_file", pj_str(fname));
    pj_set(r, "kind", pj_str(kind));
    pj_set(r, "total_size", pj_int(total));
    pj_set(r, "align", pj_int(align));
    pj_set(r, "padding_bytes", pj_int(padding));
    pj_set(r, "fields", fields ? fields : pj_arr());
    pj_set(r, "metadata", meta ? meta : pj_obj());
    return r;
}

static pj *mk_symbol(const char *name, const char *source_kind, const char *fname, const char *sym_type,
                     const char *binding, pj *address, int64_t size, const char *section) {
    pj *s = pj_obj();
    pj_set(s, "name", pj_str(name));
    pj_set(s, "source_kind", pj_str(source_kind));
    pj_set(s, "source_file", pj_str(fname));
    pj_set(s, "sym_type", pj_str(sym_type));
    pj_set(s, "binding", pj_str(binding));
    pj_set(s, "address", address ? address : pj_int(0));
    pj_set(s, "size", pj_int(size));
    pj_set(s, "section", pj_str(section));
    return s;
}

static pj *mk_cfg(const char *name, const char *source_kind, const char *fname, pj *address) {
    pj *c = pj_obj();
    pj_set(c, "name", pj_str(name));
    pj_set(c, "source_kind", pj_str(source_kind));
    pj_set(c, "source_file", pj_str(fname));
    pj_set(c, "address", address ? address : pj_null());
    pj_set(c, "stack_frame_bytes", pj_int(0));
    pj_set(c, "blocks", pj_arr());
    pj_set(c, "cyclomatic_complexity", pj_int(1));
    return c;
}

static pj *mk_block(const char *label) {
    pj *b = pj_obj();
    pj_set(b, "label", pj_str(label));
    pj_set(b, "instructions", pj_arr());
    pj_set(b, "successors", pj_arr());
    pj_set(b, "calls", pj_arr());
    return b;
}

static bool arr_has_str(const pj *a, const char *s) {
    for (size_t i = 0; i < a->n; i++) {
        if (a->v[i]->t == PJ_STR && strcmp(a->v[i]->s, s) == 0) return true;
    }
    return false;
}

static pw_re *re_get(pw_re **slot, const char *pat, int flags) {
    if (*slot == nullptr) *slot = pw_re_compile(pat, flags);
    return *slot;
}

static int64_t align_up(int64_t v, int64_t a) { return a <= 1 ? v : (v + a - 1) & ~(a - 1); }

/* ------------------------------------------------------------------ */
/* C frontend                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *name;
    int size, align;
} cprim;

static const cprim C_LP64[] = {
    {"char", 1, 1}, {"signed char", 1, 1}, {"unsigned char", 1, 1},
    {"int8_t", 1, 1}, {"uint8_t", 1, 1}, {"bool", 1, 1}, {"_Bool", 1, 1},
    {"short", 2, 2}, {"short int", 2, 2}, {"unsigned short", 2, 2},
    {"int16_t", 2, 2}, {"uint16_t", 2, 2},
    {"int", 4, 4}, {"signed int", 4, 4}, {"unsigned int", 4, 4}, {"unsigned", 4, 4},
    {"int32_t", 4, 4}, {"uint32_t", 4, 4}, {"float", 4, 4},
    {"long", 8, 8}, {"long int", 8, 8}, {"unsigned long", 8, 8},
    {"long long", 8, 8}, {"unsigned long long", 8, 8},
    {"int64_t", 8, 8}, {"uint64_t", 8, 8}, {"size_t", 8, 8}, {"ssize_t", 8, 8},
    {"double", 8, 8}, {"void*", 8, 8},
};
static const char *const WASM32_NARROW[] = { "long", "long int", "unsigned long", "size_t", "ssize_t", "void*" };

typedef struct {
    char **name;
    int64_t *size, *align;
    size_t n, cap;
} typemap;

static void tm_set(typemap *m, const char *name, int64_t size, int64_t align) {
    for (size_t i = 0; i < m->n; i++) {
        if (strcmp(m->name[i], name) == 0) { m->size[i] = size; m->align[i] = align; return; }
    }
    if (m->n == m->cap) {
        m->cap = m->cap ? m->cap * 2 : 64;
        m->name = realloc(m->name, sizeof *m->name * m->cap);
        m->size = realloc(m->size, sizeof *m->size * m->cap);
        m->align = realloc(m->align, sizeof *m->align * m->cap);
        if (!m->name || !m->size || !m->align) abort();
    }
    m->name[m->n] = pw_dup(name);
    m->size[m->n] = size;
    m->align[m->n++] = align;
}

static bool tm_get(const typemap *m, const char *name, int64_t *size, int64_t *align) {
    for (size_t i = 0; i < m->n; i++) {
        if (strcmp(m->name[i], name) == 0) { *size = m->size[i]; *align = m->align[i]; return true; }
    }
    return false;
}

static void tm_free(typemap *m) {
    for (size_t i = 0; i < m->n; i++) free(m->name[i]);
    free(m->name);
    free(m->size);
    free(m->align);
}

static pw_re *RC_BLOCKC, *RC_LINEC, *RC_TYPEDEF, *RC_BLOCK, *RC_FIELD, *RC_QUAL, *RC_FN;

void pw_bsm_parse_c(const char *text, size_t len, const char *fname, const char *abi, pj *records, pj *symbols) {
    size_t l1, n;
    char *a = pw_re_sub_empty(re_get(&RC_BLOCKC, "/\\*.*?\\*/", PW_RE_S), text, len, &l1);
    char *clean = pw_re_sub_empty(re_get(&RC_LINEC, "//.*?$", PW_RE_M), a, l1, &n);
    free(a);
    const bool w32 = strcmp(abi, "wasm32") == 0;
    const int64_t ptr = w32 ? 4 : 8;
    typemap known = {0};
    for (size_t i = 0; i < sizeof C_LP64 / sizeof C_LP64[0]; i++) {
        int sz = C_LP64[i].size, al = C_LP64[i].align;
        if (w32) {
            for (size_t k = 0; k < sizeof WASM32_NARROW / sizeof WASM32_NARROW[0]; k++) {
                if (strcmp(C_LP64[i].name, WASM32_NARROW[k]) == 0) sz = al = 4;
            }
        }
        tm_set(&known, C_LP64[i].name, sz, al);
    }
    pw_rm m;
    pw_re *td = re_get(&RC_TYPEDEF, "\\btypedef\\s+([a-zA-Z_][\\w\\s\\*]*?)\\s+([a-zA-Z_]\\w*)\\s*;", 0);
    for (size_t p = 0; pw_re_next(td, clean, n, &p, &m);) {
        char *base = pw_wsjoin(clean + m.so[1], (size_t)(m.eo[1] - m.so[1]));
        char *alias = pw_rm_dup(&m, 2, clean);
        int64_t s, al;
        if (strchr(base, '*')) tm_set(&known, alias, ptr, ptr);
        else if (tm_get(&known, base, &s, &al)) tm_set(&known, alias, s, al);
        free(base);
        free(alias);
    }
    pw_re *blk = re_get(&RC_BLOCK,
        "(typedef\\s+)?(struct|union)\\s*([a-zA-Z_]\\w*)?\\s*\\{([^}]*)\\}\\s*([a-zA-Z_]\\w*)?\\s*;", PW_RE_S);
    pw_re *fre = re_get(&RC_FIELD, "^(.*?)([a-zA-Z_]\\w*)(?:\\s*\\[\\s*(\\d+)\\s*\\])?$", 0);
    pw_re *qre = re_get(&RC_QUAL, "\\b(const|volatile|struct|union|enum)\\b", 0);
    for (size_t p = 0; pw_re_next(blk, clean, n, &p, &m);) {
        char *kind = pw_rm_dup(&m, 2, clean);
        char *tag = pw_rm_dup(&m, 3, clean);
        char *tdname = pw_rm_dup(&m, 5, clean);
        char *rec_name = tdname ? pw_dup(tdname) : tag ? pw_dup(tag)
                         : pw_fmt("anon_%s_%zu", kind, pw_cp_index(clean, (size_t)m.so[0]));
        const bool is_union = strcmp(kind, "union") == 0;
        pj *fields = pj_arr();
        int64_t offset = 0, max_align = 1, max_union = 0, padding = 0;
        pw_strv stmts = pw_split_ch(clean + m.so[4], (size_t)(m.eo[4] - m.so[4]), ';');
        for (size_t i = 0; i < stmts.n; i++) {
            char *stmt = pw_wsjoin(stmts.v[i], strlen(stmts.v[i]));
            pw_rm fm;
            if (!stmt[0] || !pw_re_match_at(fre, stmt, strlen(stmt), 0, &fm)) { free(stmt); continue; }
            char *rt0 = pw_rm_dup(&fm, 1, stmt);
            char *raw_type = pw_strip(rt0, strlen(rt0));
            free(rt0);
            char *fname_ = pw_rm_dup(&fm, 2, stmt);
            int64_t arr = 1;
            if (pw_rm_set(&fm, 3)) arr = strtoll(stmt + fm.so[3], nullptr, 10);
            const bool is_ptr = strchr(raw_type, '*') != nullptr;
            size_t bl;
            char *b0 = pw_re_sub_empty(qre, raw_type, strlen(raw_type), &bl);
            pw_buf nb = {0};
            pw_buf_put(&nb, "", 0);
            for (char *q = b0; *q; q++) if (*q != '*') pw_buf_putc(&nb, *q);
            free(b0);
            char *b1 = pw_buf_take(&nb, nullptr);
            char *base = pw_wsjoin(b1, strlen(b1));
            free(b1);
            int64_t fs, fa;
            const char *fk;
            if (is_ptr) { fs = fa = ptr; fk = "pointer"; }
            else if (tm_get(&known, base, &fs, &fa)) fk = arr > 1 ? "array" : "primitive";
            else { fs = fa = 4; fk = "unresolved"; }
            const int64_t tot = fs * arr;
            if (fa > max_align) max_align = fa;
            char *tname = arr > 1 ? pw_fmt("%s[%lld]", raw_type, (long long)arr) : pw_dup(raw_type);
            if (is_union) {
                pj_push(fields, mk_field(fname_, tname, 0, tot, fa, "union_member", ""));
                if (tot > max_union) max_union = tot;
            } else {
                const int64_t ao = align_up(offset, fa), pad = ao - offset;
                padding += pad;
                char *notes = pad ? pw_fmt("+%lldB pad", (long long)pad) : pw_dup("");
                pj_push(fields, mk_field(fname_, tname, ao, tot, fa, fk, notes));
                free(notes);
                offset = ao + tot;
            }
            free(tname);
            free(base);
            free(raw_type);
            free(fname_);
            free(stmt);
        }
        pw_strv_free(&stmts);
        int64_t total, tail;
        if (is_union) {
            total = align_up(max_union, max_align);
            tail = total - max_union;
            padding = tail;
        } else {
            total = align_up(offset, max_align);
            tail = total - offset;
            padding += tail;
        }
        tm_set(&known, rec_name, total, max_align);
        if (tag) tm_set(&known, tag, total, max_align);
        pj *meta = pj_obj();
        pj_set(meta, "abi", pj_str(abi));
        pj_set(meta, "tail_padding", pj_int(tail));
        pj_push(records, mk_record(rec_name, "c", fname, kind, total, max_align, padding, fields, meta));
        pj_push(symbols, mk_symbol(rec_name, "c", fname, "RECORD", "GLOBAL", nullptr, total, ""));
        free(kind);
        free(tag);
        free(tdname);
        free(rec_name);
    }
    pw_re *fnre = re_get(&RC_FN, "\\b([a-zA-Z_][\\w\\s\\*]+?)\\s+([a-zA-Z_]\\w*)\\s*\\(([^;{}]*)\\)\\s*(?:\\{|;)", PW_RE_M);
    for (size_t p = 0; pw_re_next(fnre, clean, n, &p, &m);) {
        char *ret = pw_strip(clean + m.so[1], (size_t)(m.eo[1] - m.so[1]));
        char *fn = pw_rm_dup(&m, 2, clean);
        static const char *const skip_n[] = { "if", "while", "for", "switch", "return", "sizeof" };
        static const char *const skip_r[] = { "typedef", "struct", "union", "return" };
        bool skip = false;
        for (size_t k = 0; k < 6; k++) skip |= strcmp(fn, skip_n[k]) == 0;
        for (size_t k = 0; k < 4; k++) skip |= pw_startswith(ret, skip_r[k]);
        if (!skip) pj_push(symbols, mk_symbol(fn, "c", fname, "FUNC", "GLOBAL", nullptr, 0, ""));
        free(ret);
        free(fn);
    }
    tm_free(&known);
    free(clean);
}

/* ------------------------------------------------------------------ */
/* COBOL frontend                                                      */
/* ------------------------------------------------------------------ */

static size_t cp_len(const char *s) { return pw_cp_index(s, strlen(s)); }

/* Byte offset of code point index i (clamped to the end). */
static size_t cp_off(const char *s, size_t i) {
    size_t k = 0, cps = 0;
    while (s[k] && cps < i) {
        k++;
        while (s[k] && ((unsigned char)s[k] & 0xC0) == 0x80) k++;
        cps++;
    }
    return k;
}

static pw_re *RB_PIC, *RB_STMT, *RB_REDEF, *RB_OCC, *RB_PICTOK;

static int64_t cobol_pic_size(const char *pic, const char *usage, const char **kind) {
    char *u = pw_upper(pic);
    int64_t digits = 0, alpha = 0;
    pw_re *re = re_get(&RB_PICTOK, "([9XAVS])(?:\\((\\d+)\\))?", 0);
    pw_rm m;
    const size_t n = strlen(u);
    for (size_t p = 0; pw_re_next(re, u, n, &p, &m);) {
        const int64_t cnt = pw_rm_set(&m, 2) ? strtoll(u + m.so[2], nullptr, 10) : 1;
        const char t = u[m.so[1]];
        if (t == '9') digits += cnt;
        else if (t == 'X' || t == 'A') alpha += cnt;
    }
    free(u);
    if (alpha > 0) { *kind = "pic_alphanumeric"; return alpha; }
    if (strstr(usage, "COMP-3") || strstr(usage, "PACKED-DECIMAL")) { *kind = "packed_decimal"; return digits / 2 + 1; }
    if (strstr(usage, "COMP") || strstr(usage, "BINARY")) {
        *kind = "comp_binary";
        return digits <= 4 ? 2 : digits <= 9 ? 4 : 8;
    }
    *kind = "pic_display";
    return digits > 1 ? digits : 1;
}

static void cobol_close(pj *rec, pj *records) {
    int64_t mx = 0;
    const pj *fields = pj_get(rec, "fields");
    for (size_t i = 0; i < fields->n; i++) {
        const int64_t e = pj_as_int(pj_get(fields->v[i], "offset")) + pj_as_int(pj_get(fields->v[i], "size"));
        if (e > mx) mx = e;
    }
    const int64_t cur = pj_as_int(pj_get(rec, "total_size"));
    pj_set(rec, "total_size", pj_int(cur > mx ? cur : mx));
    pj_push(records, rec);
}

void pw_bsm_parse_cobol(const char *text, size_t len, const char *fname, pj *records, pj *symbols) {
    pw_strv raws = pw_splitlines(text, len);
    pw_buf joined = {0};
    pw_buf_put(&joined, "", 0);
    bool first = true;
    for (size_t i = 0; i < raws.n; i++) {
        const char *raw = raws.v[i];
        const size_t L = cp_len(raw);
        if (L > 6 && raw[cp_off(raw, 6)] == '*') continue;
        const char *ls = raw;
        while (*ls && pw_isspace((unsigned char)*ls)) ls++;
        if (pw_startswith(ls, "*>")) continue;
        bool digits6 = L > 7;
        for (size_t k = 0; k < 6 && digits6; k++) digits6 = raw[k] >= '0' && raw[k] <= '9';
        char *line;
        if (digits6) {
            const size_t a = cp_off(raw, 6), b = cp_off(raw, 72);
            line = pw_strip(raw + a, b - a);
        } else {
            line = pw_strip(raw, strlen(raw));
        }
        if (line[0]) {
            if (!first) pw_buf_putc(&joined, ' ');
            pw_buf_puts(&joined, line);
            first = false;
        }
        free(line);
    }
    pw_strv_free(&raws);
    size_t jn;
    char *all = pw_buf_take(&joined, &jn);
    pw_strv stmts = pw_split_ch(all, jn, '.');
    free(all);

    pj *cur = nullptr;
    int64_t offset = 0;
    typemap offs = {0};   /* name -> (start, size) */
    pw_re *sre = re_get(&RB_STMT, "^(\\d{2})\\s+([A-Z0-9-]+)(.*)$", PW_RE_I);
    pw_re *pre = re_get(&RB_PIC, "\\bPIC(?:TURE)?\\s+(?:IS\\s+)?([^\\s]+)", 0);
    pw_re *rre = re_get(&RB_REDEF, "\\bREDEFINES\\s+([A-Z0-9-]+)", 0);
    pw_re *ore = re_get(&RB_OCC, "\\bOCCURS\\s+(\\d+)", 0);
    for (size_t i = 0; i < stmts.n; i++) {
        char *stmt = pw_wsjoin(stmts.v[i], strlen(stmts.v[i]));
        pw_rm m;
        if (!stmt[0] || !pw_re_match_at(sre, stmt, strlen(stmt), 0, &m)) { free(stmt); continue; }
        const int level = (int)strtol(stmt + m.so[1], nullptr, 10);
        char *n0 = pw_rm_dup(&m, 2, stmt), *r0 = pw_rm_dup(&m, 3, stmt);
        char *name = pw_upper(n0), *rest = pw_upper(r0);
        free(n0);
        free(r0);
        free(stmt);
        const size_t rn = strlen(rest);
        pw_rm pm;
        if (level == 88) { free(name); free(rest); continue; }
        if (level == 1) {
            if (cur) cobol_close(cur, records);
            cur = mk_record(name, "cobol", fname, "cobol_record", 0, 1, 0, nullptr, nullptr);
            offset = 0;
            for (size_t k = 0; k < offs.n; k++) free(offs.name[k]);
            offs.n = 0;
            pj_push(symbols, mk_symbol(name, "cobol", fname, "RECORD", "GLOBAL", nullptr, 0, ""));
            if (pw_re_search(pre, rest, rn, 0, &pm)) {
                char *pic = pw_rm_dup(&pm, 1, rest);
                const char *kind;
                const int64_t sz = cobol_pic_size(pic, rest, &kind);
                pj_push(pj_get(cur, "fields"), mk_field(name, pic, 0, sz, 1, kind, ""));
                pj_set(cur, "total_size", pj_int(sz));
                offset = sz;
                free(pic);
            }
            free(name);
            free(rest);
            continue;
        }
        if (cur == nullptr) { free(name); free(rest); continue; }
        pw_rm rm;
        const bool redef = pw_re_search(rre, rest, rn, 0, &rm);
        int64_t item_off = offset;
        char *notes = pw_dup("");
        if (redef) {
            char *target = pw_rm_dup(&rm, 1, rest);
            int64_t st, sz;
            if (tm_get(&offs, target, &st, &sz)) {
                item_off = st;
                free(notes);
                notes = pw_fmt("REDEFINES %s", target);
            }
            free(target);
        }
        pw_rm om;
        const int64_t occurs = pw_re_search(ore, rest, rn, 0, &om) ? strtoll(rest + om.so[1], nullptr, 10) : 1;
        if (pw_re_search(pre, rest, rn, 0, &pm)) {
            char *pic = pw_rm_dup(&pm, 1, rest);
            const char *kind;
            const int64_t unit = cobol_pic_size(pic, rest, &kind);
            const int64_t tot = unit * occurs;
            char *tname = occurs > 1 ? pw_fmt("%s x%lld", pic, (long long)occurs) : pw_dup(pic);
            pj_push(pj_get(cur, "fields"), mk_field(name, tname, item_off, tot, 1, kind, notes));
            tm_set(&offs, name, item_off, tot);
            if (!redef) offset = item_off + tot;
            free(tname);
            free(pic);
        } else {
            tm_set(&offs, name, item_off, 0);
            if (notes[0]) pj_push(pj_get(cur, "fields"), mk_field(name, "GROUP", item_off, 0, 1, "group", notes));
        }
        free(notes);
        free(name);
        free(rest);
    }
    if (cur) cobol_close(cur, records);
    tm_free(&offs);
    pw_strv_free(&stmts);
}

/* ------------------------------------------------------------------ */
/* Assembly frontend                                                   */
/* ------------------------------------------------------------------ */

static const char *const BRANCH_M[] = { "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jb",
                                        "b", "beq", "bne", "blt", "bge", "cbz", "cbnz" };
static const char *const CALL_M[] = { "call", "callq", "bl", "blr", "jal" };
static const char *const RET_M[] = { "ret", "retq", "retn", "bx" };

static bool in_set(const char *s, const char *const *set, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(s, set[i]) == 0) return true;
    }
    return false;
}
#define IN(s, set) in_set((s), (set), sizeof(set) / sizeof((set)[0]))

static void finish_cfg(pj *fn) {
    const pj *blocks = pj_get(fn, "blocks");
    const int64_t nodes = blocks->n > 1 ? (int64_t)blocks->n : 1;
    int64_t edges = 0;
    for (size_t i = 0; i < blocks->n; i++) edges += (int64_t)pj_get(blocks->v[i], "successors")->n;
    const int64_t cc = edges - nodes + 2;
    pj_set(fn, "cyclomatic_complexity", pj_int(cc > 1 ? cc : 1));
}

static pw_re *RA_CMT, *RA_GLOBL, *RA_LABEL, *RA_IMM;

void pw_bsm_parse_asm(const char *text, size_t len, const char *fname, const char *sk, pj *cfgs, pj *symbols) {
    pj *fn = nullptr, *blk = nullptr;
    pw_re *cre = re_get(&RA_CMT, "[;#].*$", 0);
    pw_re *gre = re_get(&RA_GLOBL, "^\\.(?:globl|global)\\s+([A-Za-z_.$][\\w.$]*)", 0);
    pw_re *lre = re_get(&RA_LABEL, "^([A-Za-z_.$][\\w.$]*):(.*)$", 0);
    pw_re *ire = re_get(&RA_IMM, "(?:0x([0-9a-fA-F]+)|(\\d+))", 0);
    pw_strv lines = pw_splitlines(text, len);
    for (size_t li = 0; li < lines.n; li++) {
        size_t cl;
        char *c0 = pw_re_sub_empty(cre, lines.v[li], strlen(lines.v[li]), &cl);
        char *line = pw_strip(c0, cl);
        free(c0);
        if (!line[0]) { free(line); continue; }
        pw_rm m;
        if (line[0] == '.') {
            if (pw_re_match_at(gre, line, strlen(line), 0, &m)) {
                char *g = pw_rm_dup(&m, 1, line);
                pj_push(symbols, mk_symbol(g, sk, fname, "FUNC", "GLOBAL", nullptr, 0, ""));
                free(g);
            }
            free(line);
            continue;
        }
        if (pw_re_match_at(lre, line, strlen(line), 0, &m)) {
            char *lbl = pw_rm_dup(&m, 1, line);
            char *tr = pw_strip(line + m.so[2], (size_t)(m.eo[2] - m.so[2]));
            const bool local = lbl[0] == '.' || lbl[0] == 'L';
            if (fn == nullptr || !local) {
                if (fn) {
                    pj_push(pj_get(fn, "blocks"), blk);
                    finish_cfg(fn);
                    pj_push(cfgs, fn);
                }
                fn = mk_cfg(lbl, sk, fname, nullptr);
                blk = mk_block(lbl);
                bool seen = false;
                for (size_t k = 0; k < symbols->n && !seen; k++) seen = strcmp(pj_as_str(pj_get(symbols->v[k], "name")), lbl) == 0;
                if (!seen) pj_push(symbols, mk_symbol(lbl, sk, fname, "FUNC", "LOCAL", nullptr, 0, ""));
            } else {
                if (blk) {
                    const pj *ins = pj_get(blk, "instructions");
                    char *last = pw_dup("");
                    if (ins->n) {
                        pw_strv w = pw_split_ws(ins->v[ins->n - 1]->s, ins->v[ins->n - 1]->slen, -1);
                        free(last);
                        last = pw_lower(w.n ? w.v[0] : "");
                        pw_strv_free(&w);
                    }
                    pj *succ = pj_get(blk, "successors");
                    if (strcmp(last, "jmp") != 0 && strcmp(last, "b") != 0 && !IN(last, RET_M) && !arr_has_str(succ, lbl))
                        pj_push(succ, pj_str(lbl));
                    free(last);
                    pj_push(pj_get(fn, "blocks"), blk);
                }
                blk = mk_block(lbl);
            }
            free(lbl);
            if (!tr[0]) { free(tr); free(line); continue; }
            free(line);
            line = tr;
        }
        if (fn == nullptr) {
            fn = mk_cfg("_start", sk, fname, nullptr);
            blk = mk_block("_start");
        }
        pj_push(pj_get(blk, "instructions"), pj_str(line));
        pw_strv parts = pw_split_ws(line, strlen(line), 1);
        char *op = pw_lower(parts.v[0]);
        char *operands = parts.n > 1 ? pw_strip(parts.v[1], strlen(parts.v[1])) : pw_dup("");
        pw_strv_free(&parts);
        if ((strcmp(op, "sub") == 0 || strcmp(op, "subq") == 0) && (strstr(operands, "rsp") || strstr(operands, "sp"))) {
            if (pw_re_search(ire, operands, strlen(operands), 0, &m)) {
                const uint64_t v = pw_rm_set(&m, 1) ? strtoull(operands + m.so[1], nullptr, 16)
                                                    : strtoull(operands + m.so[2], nullptr, 10);
                const pj *cur = pj_get(fn, "stack_frame_bytes");
                if (v > (uint64_t)pj_as_int(cur)) pj_set(fn, "stack_frame_bytes", pj_uint(v));
            }
        }
        if (IN(op, CALL_M) || IN(op, BRANCH_M)) {
            pw_strv first = pw_split_ch(operands, strlen(operands), ',');
            char *target = pw_strip(first.v[0], strlen(first.v[0]));
            pw_strv_free(&first);
            if (IN(op, CALL_M)) {
                const char *t = target;
                while (*t == '*') t++;
                pj_push(pj_get(blk, "calls"), pj_str(t));
            } else if (!arr_has_str(pj_get(blk, "successors"), target)) {
                pj_push(pj_get(blk, "successors"), pj_str(target));
            }
            free(target);
        }
        free(op);
        free(operands);
        free(line);
    }
    if (fn) {
        pj_push(pj_get(fn, "blocks"), blk);
        finish_cfg(fn);
        pj_push(cfgs, fn);
    }
    pw_strv_free(&lines);
}

/* ------------------------------------------------------------------ */
/* Cross-source linking                                                */
/* ------------------------------------------------------------------ */

void pw_bsm_analyze(pw_holo_ir *ir) {
    pw_strv norms = {0};
    pj *groups = pj_arr();   /* parallel to norms: arrays of symbol refs (copies) */
    for (size_t i = 0; i < ir->symbols->n; i++) {
        const pj *s = ir->symbols->v[i];
        char *low = pw_lower(pj_as_str(pj_get(s, "name")));
        pw_buf b = {0};
        pw_buf_put(&b, "", 0);
        for (const char *q = low; *q; q++) {
            if ((*q >= 'a' && *q <= 'z') || (*q >= '0' && *q <= '9')) pw_buf_putc(&b, *q);
        }
        free(low);
        char *norm = pw_buf_take(&b, nullptr);
        if (strlen(norm) < 2) { free(norm); continue; }
        size_t g = 0;
        for (; g < norms.n; g++) {
            if (strcmp(norms.v[g], norm) == 0) break;
        }
        if (g == norms.n) { pw_strv_push(&norms, norm); pj_push(groups, pj_arr()); }
        else free(norm);
        pj_push(groups->v[g], pj_int((int64_t)i));
    }
    for (size_t g = 0; g < norms.n; g++) {
        const pj *grp = groups->v[g];
        bool multi = false;
        const char *k0 = pj_as_str(pj_get(ir->symbols->v[grp->v[0]->i], "source_kind"));
        for (size_t k = 1; k < grp->n && !multi; k++)
            multi = strcmp(pj_as_str(pj_get(ir->symbols->v[grp->v[k]->i], "source_kind")), k0) != 0;
        if (!multi) continue;
        pj *ents = pj_arr();
        for (size_t k = 0; k < grp->n; k++) {
            const pj *s = ir->symbols->v[grp->v[k]->i];
            pj_push(ents, pj_strown(pw_fmt("%s:%s (%s)", pj_as_str(pj_get(s, "source_kind")),
                                           pj_as_str(pj_get(s, "name")), pj_as_str(pj_get(s, "source_file")))));
        }
        pj *cl = pj_obj();
        pj_set(cl, "canonical", pj_str(norms.v[g]));
        pj_set(cl, "entities", ents);
        pj_push(ir->cross_links, cl);
    }
    pj_free(groups);
    pw_strv_free(&norms);
}
