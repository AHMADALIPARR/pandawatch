/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* holo-reverse: .holo.wasm -> C23 header (holo_reversed_c23.h), CompCert
 * Ctypes composites (holo_compcert.v) and Lean 4 HoloDSL records with
 * wa_holo! layout theorems (HoloDSL.lean). The module is read with the bsm
 * inspector and must pass its SHA-256 integrity check. C23.
 *   holo-reverse wasm_file --out-dir DIR [--lean-import MODULE]
 * --lean-import makes HoloDSL.lean import MODULE (the DSL definitions, e.g.
 * HoloDSL.HoloDSL_checked) and emit only the records, in namespace
 * HoloReversed. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_bsm.h"
#include "pw_cli.h"
#include "pw_json.h"
#include "pw_text.h"

static const char USAGE[] = "usage: holo-reverse [-h] --out-dir OUT_DIR [--lean-import MODULE] wasm_file";
static const char HELP[] =
    "usage: holo-reverse [-h] --out-dir OUT_DIR [--lean-import MODULE] wasm_file\n"
    "\n"
    "Reverse .holo.wasm to C23, CompCert, and Lean 4 DSL\n"
    "\n"
    "positional arguments:\n"
    "  wasm_file             Input .holo.wasm file\n"
    "\n"
    "options:\n"
    "  -h, --help            show this help message and exit\n"
    "  --out-dir OUT_DIR     Output directory\n"
    "  --lean-import MODULE  Import the HoloDSL definitions from MODULE and emit\n"
    "                        only the records\n";

/* Python str() of a JSON value inside an f-string. */
static char *pystr(const pj *v) {
    if (v == nullptr) return pw_dup("");
    if (v->t == PJ_STR) return pw_dup(v->s);
    return pj_pyrepr(v);
}

static const pj *getd(const pj *o, const char *k) {
    return o && o->t == PJ_OBJ ? pj_get(o, k) : nullptr;
}

/* re.sub(r"[^a-zA-Z0-9_]", "_", s), then "r_" if empty or digit-led. */
static char *c_ident(const char *s) {
    pw_buf b = {0};
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        const unsigned c = *p;
        size_t len = 1;
        if (c >= 0xF0) len = 4; else if (c >= 0xE0) len = 3; else if (c >= 0xC0) len = 2;
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
        pw_buf_putc(&b, ok ? (char)c : '_');
        size_t adv = 1;
        while (adv < len && p[adv] && (p[adv] & 0xC0) == 0x80) adv++;
        p += adv;
    }
    pw_buf_putc(&b, 0);
    char *r = b.p;
    if (r[0] == 0 || (r[0] >= '0' && r[0] <= '9')) {
        char *t = pw_fmt("r_%s", r);
        free(r);
        return t;
    }
    return r;
}

static char *ident2(const char *prefix, const pj *rec) {
    char *src = pystr(pj_get(rec, "source")), *nm = pystr(pj_get(rec, "name"));
    char *raw = pw_fmt("%s%s_%s", prefix, src, nm);
    char *r = c_ident(raw);
    free(src); free(nm); free(raw);
    return r;
}

static int64_t iget(const pj *o, const char *k, int64_t dflt) {
    const pj *v = getd(o, k);
    return v ? pj_as_int(v) : dflt;
}

static const char *c23_field_type(const pj *f) {
    const pj *kv = getd(f, "kind");
    const char *kind = kv && kv->t == PJ_STR ? kv->s : "primitive";
    const int64_t sz = iget(f, "size", 4);
    const pj *tv = getd(f, "type_name");
    const char *t = tv && tv->t == PJ_STR ? tv->s : "";
    if (strcmp(kind, "pointer") == 0) return "void *";
    if (!strcmp(kind, "pic_alphanumeric") || !strcmp(kind, "pic_display") || !strcmp(kind, "packed_decimal") ||
        !strcmp(kind, "text") || !strcmp(kind, "blob")) return "uint8_t";
    if (strstr(t, "char") && strchr(t, '[')) return "char";
    if (sz == 1) return "uint8_t";
    if (sz == 2) return "uint16_t";
    if (sz == 4) {
        char *st = pw_strip(t, strlen(t));
        const bool sgn = strstr(t, "int32") || strcmp(st, "int") == 0;
        free(st);
        return sgn ? "int32_t" : "uint32_t";
    }
    if (sz == 8) return strstr(t, "int64") ? "int64_t" : "uint64_t";
    return "uint8_t";
}

static int64_t type_bytes(const char *c) {
    if (!strcmp(c, "uint16_t")) return 2;
    if (!strcmp(c, "int32_t") || !strcmp(c, "uint32_t")) return 4;
    if (!strcmp(c, "int64_t") || !strcmp(c, "uint64_t") || !strcmp(c, "void *")) return 8;
    return 1;
}

static const pj *empty_arr(void) {
    static pj e = { .t = PJ_ARR };
    return &e;
}

static const pj *layer(const pj *report, const char *name) {
    const pj *v = getd(pj_get(report, "layers"), name);
    return v ? v : empty_arr();
}

static char *str_or(const pj *m, const char *k, const char *dflt) {
    const pj *v = getd(m, k);
    return v ? pystr(v) : pw_dup(dflt);
}

static char *emit_c23(const pj *report) {
    const pj *man = pj_get(report, "manifest");
    const pj *layouts = layer(report, "holo.layouts");
    const pj *cfgs = layer(report, "holo.cfg");
    char *fmt = str_or(man, "format", "wasm-holo/1.0"), *root = str_or(man, "root_sha256", "");
    const pj *ml = getd(man, "layers");
    pw_buf b = {0};
    pw_buf_printf(&b,
        "/*\n"
        " * Auto-generated by holo_reverse.py from %s\n"
        " * Root SHA-256: %s\n"
        " * Target: ISO/IEC 9899:2024 (C23) with C11/C2x compiler compatibility\n"
        " */\n"
        "#ifndef HOLO_REVERSED_C23_H\n"
        "#define HOLO_REVERSED_C23_H\n"
        "\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "#include <stdalign.h>\n"
        "\n"
        "#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L\n"
        "#  define HOLO_CONSTEXPR constexpr\n"
        "#  define HOLO_ENUM_BASE(T) : T\n"
        "#else\n"
        "#  define HOLO_CONSTEXPR static const\n"
        "#  define HOLO_ENUM_BASE(T)\n"
        "#  ifndef static_assert\n"
        "#    define static_assert _Static_assert\n"
        "#  endif\n"
        "#endif\n"
        "\n"
        "/* Recursive C23 Holographic AST/Semantic Node */\n"
        "typedef enum HoloNodeKind HOLO_ENUM_BASE(uint32_t) {\n"
        "    HOLO_NODE_MANIFEST = 0,\n"
        "    HOLO_NODE_RECORD   = 1,\n"
        "    HOLO_NODE_FIELD    = 2,\n"
        "    HOLO_NODE_CFG      = 3,\n"
        "    HOLO_NODE_SYMBOL   = 4,\n"
        "} HoloNodeKind;\n"
        "\n"
        "typedef struct HoloNode HoloNode;\n"
        "struct HoloNode {\n"
        "    HoloNodeKind kind;\n"
        "    uint32_t     byte_size;\n"
        "    uint32_t     align;\n"
        "    uint32_t     offset;\n"
        "    alignas(8) const char *name;\n"
        "    struct HoloNode *children;    /* recursive child array */\n"
        "    size_t           child_count;\n"
        "    struct HoloNode *cross_link;  /* recursive cross-source link */\n"
        "};\n"
        "\n"
        "HOLO_CONSTEXPR uint32_t HOLO_LAYER_COUNT = %zu;\n"
        "HOLO_CONSTEXPR uint32_t HOLO_CFG_COUNT   = %zu;\n"
        "\n",
        fmt, root, (ml ? ml->n : 0) + 1, cfgs->n);
    for (size_t i = 0; i < layouts->n; i++) {
        const pj *rec = layouts->v[i];
        char *rname = ident2("Holo_", rec);
        const int64_t total = pj_as_int(pj_get(rec, "size"));
        int64_t align = pj_as_int(pj_get(rec, "align"));
        if (align < 1) align = 1;
        const pj *fields = getd(rec, "fields");
        if (fields == nullptr) fields = empty_arr();
        char *src = pystr(pj_get(rec, "source")), *nm = pystr(pj_get(rec, "name"));
        pw_buf_printf(&b, "/* Reversed from %s::%s (size=%lldB, align=%lldB) */\n", src, nm, (long long)total, (long long)align);
        pw_buf_printf(&b, "typedef struct %s {\n", rname);
        free(src); free(nm);
        int64_t cursor = 0, pad_idx = 0;
        bool first = true;
        pw_strv names = {0};
        pw_buf asserts = {0};
        for (size_t k = 0; k < fields->n; k++) {
            const pj *f = fields->v[k];
            const int64_t off = pj_as_int(pj_get(f, "offset")), sz = pj_as_int(pj_get(f, "size"));
            char *tn = pystr(pj_get(f, "type_name"));
            if (off < cursor) {
                char *fn = pystr(pj_get(f, "name"));
                char *notes = str_or(f, "notes", "");
                pw_buf_printf(&b, "    /* OVERLAY @ %lld..%lld: %s (%s) %s */\n", (long long)off, (long long)(off + sz), fn, tn, notes);
                free(fn); free(notes); free(tn);
                continue;
            }
            if (off > cursor) {
                if (first && align > 1) pw_buf_printf(&b, "    alignas(%lld) ", (long long)align);
                else pw_buf_puts(&b, "    ");
                pw_buf_printf(&b, "uint8_t _pad_%lld[%lld];\n", (long long)pad_idx, (long long)(off - cursor));
                pad_idx++;
                cursor = off;
                first = false;
            }
            char *raw = pystr(pj_get(f, "name"));
            char *fname = c_ident(raw);
            free(raw);
            if (sz == 0) {
                pw_buf_printf(&b, "    /* GROUP %s */\n", fname);
                free(fname); free(tn);
                continue;
            }
            const char *ctype = c23_field_type(f);
            int64_t tb = type_bytes(ctype);
            if (align == 1 || off % tb != 0) { ctype = "uint8_t"; tb = 1; }
            char *ap = first && align > 1 ? pw_fmt("alignas(%lld) ", (long long)align) : pw_dup("");
            first = false;
            if (sz > tb && sz % tb == 0)
                pw_buf_printf(&b, "    %s%s %s[%lld]; /* off=%lld, %s */\n", ap, ctype, fname, (long long)(sz / tb), (long long)off, tn);
            else if (sz > tb)
                pw_buf_printf(&b, "    %suint8_t %s[%lld]; /* off=%lld, %s */\n", ap, fname, (long long)sz, (long long)off, tn);
            else
                pw_buf_printf(&b, "    %s%s %s; /* off=%lld, %s */\n", ap, ctype, fname, (long long)off, tn);
            pw_buf_printf(&asserts, "static_assert(offsetof(%s, %s) == %lld, \"%s.%s offset mismatch\");\n",
                          rname, fname, (long long)off, rname, fname);
            free(ap); free(fname); free(tn);
            cursor = off + sz;
        }
        if (cursor < total) pw_buf_printf(&b, "    uint8_t _tail_pad[%lld];\n", (long long)(total - cursor));
        pw_buf_printf(&b, "} %s;\n", rname);
        if (total > 0) pw_buf_printf(&b, "static_assert(sizeof(%s) >= %lld, \"%s size mismatch\");\n", rname, (long long)total, rname);
        if (asserts.n) pw_buf_put(&b, asserts.p, asserts.n);
        pw_buf_puts(&b, "\n");
        free(asserts.p);
        pw_strv_free(&names);
        free(rname);
    }
    pw_buf_puts(&b, "#endif /* HOLO_REVERSED_C23_H */");
    free(fmt); free(root);
    pw_buf_putc(&b, 0);
    return b.p;
}

static char *emit_coq(const pj *report) {
    const pj *man = pj_get(report, "manifest");
    const pj *layouts = layer(report, "holo.layouts");
    char *fmt = str_or(man, "format", "wasm-holo/1.0"), *root = str_or(man, "root_sha256", "");
    pw_buf b = {0};
    pw_buf_printf(&b,
        "(*\n"
        " * CompCert Ctypes Reversal from %s\n"
        " * Root SHA-256: %s\n"
        " *)\n"
        "Require Import Coq.Lists.List.\n"
        "Require Import Coq.ZArith.ZArith.\n"
        "Require Import compcert.common.AST.\n"
        "Require Import compcert.cfrontend.Ctypes.\n"
        "Require Import compcert.lib.Integers.\n"
        "Import ListNotations.\n"
        "Open Scope Z_scope.\n"
        "\n"
        "(* Identifier allocation for reversed Wasm Holo composites *)\n"
        "Definition _holo_node : ident := 1%%positive.\n"
        "Definition _kind      : ident := 2%%positive.\n"
        "Definition _byte_size : ident := 3%%positive.\n"
        "Definition _children  : ident := 4%%positive.\n"
        "\n"
        "Definition holo_node_composite : composite_definition :=\n"
        "  Composite _holo_node Struct\n"
        "    (Member_plain _kind (Tint I32 Unsigned noattr) ::\n"
        "     Member_plain _byte_size (Tint I32 Unsigned noattr) ::\n"
        "     Member_plain _children (Tpointer (Tstruct _holo_node noattr) noattr) :: nil)\n"
        "    noattr.\n",
        fmt, root);
    long long next_id = 10;
    for (size_t i = 0; i < layouts->n; i++) {
        const pj *rec = layouts->v[i];
        char *rname = ident2("holo_", rec);
        pw_buf_printf(&b, "\nDefinition _%s : ident := %lld%%positive.", rname, next_id++);
        pw_buf mem = {0};
        const pj *fields = getd(rec, "fields");
        for (size_t k = 0; fields && k < fields->n; k++) {
            const pj *f = fields->v[k];
            const int64_t sz = pj_as_int(pj_get(f, "size"));
            if (sz <= 0) continue;
            char *raw = pystr(pj_get(f, "name"));
            char *fname = c_ident(raw);
            free(raw);
            pw_buf_printf(&b, "\nDefinition _%s_%s : ident := %lld%%positive.", rname, fname, next_id++);
            char *cty = sz == 1 ? pw_dup("(Tint I8 Unsigned noattr)")
                      : sz == 2 ? pw_dup("(Tint I16 Unsigned noattr)")
                      : sz == 4 ? pw_dup("(Tint I32 Unsigned noattr)")
                      : sz == 8 ? pw_dup("(Tlong Unsigned noattr)")
                      : pw_fmt("(Tarray (Tint I8 Unsigned noattr) %lld noattr)", (long long)sz);
            if (mem.n) pw_buf_puts(&mem, " ::\n     ");
            pw_buf_printf(&mem, "Member_plain _%s_%s %s", rname, fname, cty);
            free(cty); free(fname);
        }
        pw_buf_puts(&mem, mem.n ? " :: nil" : "nil");
        pw_buf_putc(&mem, 0);
        char *size = pystr(pj_get(rec, "size")), *al = pystr(pj_get(rec, "align"));
        pw_buf_printf(&b,
            "\nDefinition %s_composite : composite_definition :=\n"
            "  Composite _%s Struct\n"
            "    (%s)\n"
            "    noattr.\n"
            "\n"
            "Record %s_holo_witness : Prop := {\n"
            "  %s_expected_size  := %s;\n"
            "  %s_expected_align := %s\n"
            "}.\n",
            rname, rname, mem.p, rname, rname, size, rname, al);
        free(size); free(al); free(mem.p); free(rname);
    }
    free(fmt); free(root);
    pw_buf_putc(&b, 0);
    return b.p;
}

static const char LEAN_DSL[] =
    "import Lean\n"
    "\n"
    "namespace HoloDSL\n"
    "\n"
    "structure FieldSpec where\n"
    "  name   : String\n"
    "  offset : Nat\n"
    "  size   : Nat\n"
    "  align  : Nat\n"
    "  deriving Repr, BEq\n"
    "\n"
    "structure HoloRecord where\n"
    "  name      : String\n"
    "  totalSize : Nat\n"
    "  align     : Nat\n"
    "  fields    : List FieldSpec\n"
    "  deriving Repr\n"
    "\n"
    "def FieldSpec.within (f : FieldSpec) (limit : Nat) : Prop :=\n"
    "  f.offset + f.size <= limit\n"
    "\n"
    "def HoloRecord.allWithin (r : HoloRecord) : Prop :=\n"
    "  \xe2\x88\x80 f \xe2\x88\x88 r.fields, f.within r.totalSize\n"
    "\n"
    "def HoloRecord.aligned (r : HoloRecord) : Prop :=\n"
    "  r.align > 0 \xe2\x88\xa7 r.totalSize % r.align = 0\n"
    "\n"
    "-- ==========================================================================\n"
    "-- Custom Lean 4 Macro DSL: Rust ABI (`rust_struct!`) + Wasm (`wa_holo!`)\n"
    "-- ==========================================================================\n"
    "\n"
    "declare_syntax_cat holoField\n"
    "syntax ident \":\" ident \"@\" num \":\" num \"align\" num : holoField\n"
    "\n"
    "-- Pipe Rust-style struct macro into a Lean HoloRecord\n"
    "syntax \"rust_struct!\" ident \"{\" holoField,* \"}\" \"size\" num \"align\" num : command\n"
    "\n"
    "macro_rules\n"
    "  | `(rust_struct! $name:ident { $[$f:ident : $_ty:ident @ $off:num : $sz:num align $al:num],* } size $tot:num align $ral:num) =>\n"
    "    `(def $name : HoloRecord :=\n"
    "        { name := $(Lean.quote name.getId.toString),\n"
    "          totalSize := $tot,\n"
    "          align := $ral,\n"
    "          fields := [ $[{ name := $(Lean.quote f.getId.toString), offset := $off, size := $sz, align := $al }],* ] })\n"
    "\n"
    "-- Pipe Wasm Holo (`wa_holo!`) layer witness directly into Lean 4 lemmas\n"
    "syntax \"wa_holo!\" ident \"(\" str \")\" \"=>\" ident : command\n"
    "\n"
    "macro_rules\n"
    "  | `(wa_holo! $thmName:ident ( $_sec:str ) => $recName:ident) =>\n"
    "    `(lemma $thmName : $recName.allWithin \xe2\x88\xa7 $recName.aligned := by\n"
    "        constructor\n"
    "        \xc2\xb7 intro f hf\n"
    "          simp [$recName, FieldSpec.within] at hf \xe2\x8a\xa2\n"
    "          rcases hf with h | h <;> try omega\n"
    "        \xc2\xb7 simp [$recName, HoloRecord.aligned])\n"
    "\n";

/* FieldSpec.disjoint: one field ends at or before the other starts. */
static int lean_fields_disjoint(const int64_t *off, const int64_t *sz, size_t n) {
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (!(off[i] + sz[i] <= off[j] || off[j] + sz[j] <= off[i])) return 0;
        }
    }
    return 1;
}

static char *emit_lean(const pj *report, const char *import_mod) {
    const pj *man = pj_get(report, "manifest");
    const pj *layouts = layer(report, "holo.layouts");
    char *fmt = str_or(man, "format", "wasm-holo/1.0"), *root = str_or(man, "root_sha256", "");
    pw_buf b = {0};
    pw_buf_printf(&b,
        "/-\n"
        "  HoloDSL.lean \xe2\x80\x94 Custom Lean 4 DSL piping Rust & Wasm (wa) macros into Lean Lemmas\n"
        "  Source: %s | Root SHA-256: %s\n"
        "-/\n", fmt, root);
    if (import_mod) pw_buf_printf(&b, "import %s\n\nnamespace HoloReversed\nopen HoloDSL\n\n", import_mod);
    else pw_buf_puts(&b, LEAN_DSL);
    pw_buf_puts(&b,
        "-- ==========================================================================\n"
        "-- Reversed Wasm Holo Records & Auto-Generated Lemmas\n"
        "-- ==========================================================================\n"
        "\n");
    for (size_t i = 0; i < layouts->n; i++) {
        const pj *rec = layouts->v[i];
        char *rname = ident2("", rec);
        const int64_t total = pj_as_int(pj_get(rec, "size"));
        int64_t align = pj_as_int(pj_get(rec, "align"));
        if (align < 1) align = 1;
        const int64_t at = total > 0 ? ((total + align - 1) / align) * align : align;
        pw_buf fl = {0};
        int64_t *offs = nullptr, *szs = nullptr;
        size_t nf = 0;
        const pj *fields = getd(rec, "fields");
        for (size_t k = 0; fields && k < fields->n; k++) {
            const pj *f = fields->v[k];
            const int64_t off = pj_as_int(pj_get(f, "offset")), sz = pj_as_int(pj_get(f, "size"));
            int64_t fal = iget(f, "align", 1);
            if (fal < 1) fal = 1;
            if (sz <= 0 || off + sz > at) continue;
            char *raw = pystr(pj_get(f, "name"));
            char *fname = c_ident(raw);
            free(raw);
            if (fl.n) pw_buf_puts(&fl, ", ");
            pw_buf_printf(&fl, "%s : u8 @ %lld : %lld align %lld", fname, (long long)off, (long long)sz, (long long)fal);
            free(fname);
            int64_t *no = realloc(offs, (nf + 1) * sizeof *offs);
            int64_t *ns = realloc(szs, (nf + 1) * sizeof *szs);
            if (no == nullptr || ns == nullptr) pw_die("out of memory");
            offs = no; szs = ns;
            offs[nf] = off; szs[nf] = sz; nf++;
        }
        pw_buf_putc(&fl, 0);
        pw_buf_printf(&b, "rust_struct! %s { %s } size %lld align %lld\n", rname, fl.p, (long long)at, (long long)align);
        if (import_mod && !lean_fields_disjoint(offs, szs, nf)) {
            pw_buf_printf(&b,
                "theorem %s_sound : HoloRecord.allWithin %s \xe2\x88\xa7 HoloRecord.aligned %s := by\n"
                "  decide\n\n", rname, rname, rname);
        } else {
            pw_buf_printf(&b, "wa_holo! %s_sound (\"holo.layouts\") => %s\n\n", rname, rname);
        }
        free(fl.p); free(offs); free(szs); free(rname);
    }
    pw_buf_puts(&b, import_mod ? "end HoloReversed" : "end HoloDSL");
    free(fmt); free(root);
    pw_buf_putc(&b, 0);
    return b.p;
}

static void write_text(const char *path, const char *s) {
    if (pw_spit(path, s, strlen(s)) != 0) pw_die("OSError: [Errno %d] %s: '%s'", errno, strerror(errno), path);
}

int main(int argc, char **argv) {
    const char *out_dir = nullptr, *lean_import = nullptr, *pos[1] = {nullptr};
    pw_opt opts[] = { { nullptr, "--out-dir", true, &out_dir }, { nullptr, "--lean-import", true, &lean_import } };
    const int np = pw_cli_scan(argc, argv, 1, opts, 2, pos, 1, false, USAGE, "holo-reverse", HELP);
    if (np < 1 && out_dir == nullptr) pw_cli_error(USAGE, "holo-reverse", "the following arguments are required: wasm_file, --out-dir");
    if (np < 1) pw_cli_error(USAGE, "holo-reverse", "the following arguments are required: wasm_file");
    if (out_dir == nullptr) pw_cli_error(USAGE, "holo-reverse", "the following arguments are required: --out-dir");
    size_t len;
    uint8_t *w = pw_slurp(pos[0], &len);
    if (w == nullptr) pw_die("FileNotFoundError: [Errno %d] %s: '%s'", errno, strerror(errno), pos[0]);
    char err[512];
    pj *report = pw_bsm_inspect(w, len, err, sizeof err);
    free(w);
    if (report == nullptr) pw_die("%s", err);
    if (!pj_truthy(pj_get(report, "integrity_verified"))) pw_die("RuntimeError: Wasm Holo SHA-256 integrity verification failed!");
    char *dir = pw_path_norm(out_dir);
    if (pw_mkdirs(dir) != 0) pw_die("OSError: [Errno %d] %s: '%s'", errno, strerror(errno), dir);
    char *c23 = pw_path_join(dir, "holo_reversed_c23.h");
    char *coq = pw_path_join(dir, "holo_compcert.v");
    char *lean = pw_path_join(dir, "HoloDSL.lean");
    char *t = emit_c23(report);
    write_text(c23, t);
    free(t);
    t = emit_coq(report);
    write_text(coq, t);
    free(t);
    t = emit_lean(report, lean_import);
    write_text(lean, t);
    free(t);
    printf("Generated:\n  - %s\n  - %s\n  - %s\n", c23, coq, lean);
    free(c23); free(coq); free(lean); free(dir);
    pj_free(report);
    return 0;
}
