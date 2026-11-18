/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* BSM ELF frontend: ELF32 / ELF64 (either byte order) header, section
 * headers, .symtab and .dynsym. For x86-64 the CFG of every sized FUNC
 * symbol in an executable section comes from the repo's own decoder
 * (asm/pw_x86_decode.S, formatted by xasm/pw_x86_text.c): one block per
 * function, direct jmp / jcc targets as successors, direct call targets
 * resolved to symbols. Decoding stops at the first instruction outside the
 * decoder's subset, which is recorded as "(bad)". C23. */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_bsm.h"
#include "pw_text.h"

#ifdef PW_BSM_X86
#include "pw_x86.h"
#endif

typedef struct {
    uint32_t name_off, type, link;
    uint64_t flags, addr, offset, size, entsize;
    char *name;
} elf_sec;

typedef struct {
    const uint8_t *d;
    size_t n;
    bool le;
    const char *path;
} elf_in;

[[noreturn]] static void short_read(const elf_in *e, size_t need) {
    pw_die("struct.error: unpack_from requires a buffer of at least %zu bytes (%s has %zu)", need, e->path, e->n);
}

static uint64_t rd(const elf_in *e, uint64_t off, int size) {
    if (off + (uint64_t)size > e->n) short_read(e, (size_t)(off + (uint64_t)size));
    uint64_t v = 0;
    for (int i = 0; i < size; i++) {
        const uint64_t b = e->d[off + (uint64_t)i];
        v |= e->le ? b << (8 * i) : b << (8 * (size - 1 - i));
    }
    return v;
}

/* data[off:off+size] with Python slice clamping. */
static void slice(const elf_in *e, uint64_t off, uint64_t size, const uint8_t **p, size_t *n) {
    if (off >= e->n) { *p = e->d; *n = 0; return; }
    *p = e->d + off;
    *n = (size_t)((off + size > e->n) ? e->n - off : size);
}

static char *read_cstr(const uint8_t *buf, size_t n, uint64_t off) {
    if (off >= n) return pw_dup("");
    const uint8_t *z = memchr(buf + off, 0, n - (size_t)off);
    const size_t l = z ? (size_t)(z - (buf + off)) : n - (size_t)off;
    return pw_decode_utf8(buf + off, l, nullptr);
}

static const char *stt_name(unsigned t) {
    static const char *const n[] = { "NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE" };
    return t < 5 ? n[t] : "OTHER";
}
static const char *stb_name(unsigned b) {
    static const char *const n[] = { "LOCAL", "GLOBAL", "WEAK" };
    return b < 3 ? n[b] : "LOCAL";
}

static pj *hex_str(uint64_t v) { return pj_strown(pw_fmt("0x%" PRIx64, v)); }

typedef struct {
    char *name;
    uint64_t value, size;
    uint32_t shndx;
    unsigned type;
} elf_sym;

#ifdef PW_BSM_X86
static int cmp_fn(const void *a, const void *b) {
    const elf_sym *x = a, *y = b;
    if (x->shndx != y->shndx) return x->shndx < y->shndx ? -1 : 1;
    if (x->value != y->value) return x->value < y->value ? -1 : 1;
    return 0;
}

static char *resolve(const elf_sym *syms, size_t n, uint64_t target) {
    for (size_t i = 0; i < n; i++) {
        if (syms[i].value == target && syms[i].type == 2) return pw_dup(syms[i].name);
    }
    for (size_t i = 0; i < n; i++) {
        if (syms[i].value == target && syms[i].name[0]) return pw_dup(syms[i].name);
    }
    for (size_t i = 0; i < n; i++) {
        if (syms[i].type == 2 && syms[i].size && target > syms[i].value && target < syms[i].value + syms[i].size)
            return pw_fmt("%s+0x%" PRIx64, syms[i].name, target - syms[i].value);
    }
    return nullptr;
}

static bool is_branch(const char *m) {
    static const char *const b[] = { "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jb" };
    for (size_t i = 0; i < sizeof b / sizeof b[0]; i++) {
        if (strcmp(m, b[i]) == 0) return true;
    }
    return false;
}

static void x86_cfgs(const elf_in *e, const elf_sec *secs, size_t nsec, elf_sym *syms, size_t nsyms,
                     const char *fname, pj *cfgs) {
    elf_sym *fns = malloc(sizeof *fns * (nsyms ? nsyms : 1));
    if (fns == nullptr) abort();
    size_t nf = 0;
    for (size_t i = 0; i < nsyms; i++) {
        const elf_sym *s = &syms[i];
        if (s->type != 2 || s->size == 0 || s->shndx == 0 || s->shndx >= nsec) continue;
        const elf_sec *sec = &secs[s->shndx];
        if (!(sec->flags & 4) || sec->type == 8) continue;
        bool dup = false;
        for (size_t k = 0; k < nf && !dup; k++) dup = fns[k].shndx == s->shndx && fns[k].value == s->value;
        if (!dup) fns[nf++] = *s;
    }
    qsort(fns, nf, sizeof *fns, cmp_fn);
    for (size_t f = 0; f < nf; f++) {
        const elf_sec *sec = &secs[fns[f].shndx];
        const uint64_t start = fns[f].value;
        const uint64_t rel = start - sec->addr;
        const uint8_t *code;
        size_t avail;
        slice(e, sec->offset + rel, fns[f].size, &code, &avail);
        pj *cfg = pj_obj();
        pj_set(cfg, "name", pj_str(fns[f].name));
        pj_set(cfg, "source_kind", pj_str("elf"));
        pj_set(cfg, "source_file", pj_str(fname));
        pj_set(cfg, "address", pj_uint(start));
        pj_set(cfg, "stack_frame_bytes", pj_int(0));
        pj *blk = pj_obj();
        pj_set(blk, "label", hex_str(start));
        pj *ins = pj_arr(), *succ = pj_arr(), *calls = pj_arr();
        size_t pos = 0;
        while (pos < avail) {
            pw_x86_insn_t in;
            const size_t l = pw_x86_decode(code + pos, avail - pos, &in);
            char text[160];
            if (l == 0 || pw_x86_format(&in, start + pos, text, sizeof text) < 0) {
                pj_push(ins, pj_str("(bad)"));
                break;
            }
            pj_push(ins, pj_str(text));
            char mnem[32];
            sscanf(text, "%31s", mnem);
            const uint64_t target = start + pos + l + (uint64_t)in.imm;
            const bool direct = !in.has_modrm && (in.opcode == 0xE8 || in.opcode == 0xE9 || in.opcode == 0xEB ||
                                                  (in.opcode >= 0x70 && in.opcode <= 0x7F) || in.escape);
            if (strcmp(mnem, "call") == 0) {
                if (direct) {
                    char *t = resolve(syms, nsyms, target);
                    if (t) pj_push(calls, pj_strown(t));
                }
            } else if (is_branch(mnem) && direct) {
                pj_push(succ, hex_str(target));
            }
            pos += l;
        }
        const int64_t edges = (int64_t)succ->n;
        pj_set(blk, "instructions", ins);
        pj_set(blk, "successors", succ);
        pj_set(blk, "calls", calls);
        pj *blocks = pj_arr();
        pj_push(blocks, blk);
        pj_set(cfg, "blocks", blocks);
        pj_set(cfg, "cyclomatic_complexity", pj_int(edges + 1 > 1 ? edges + 1 : 1));
        pj_push(cfgs, cfg);
    }
    free(fns);
}
#endif

pj *pw_bsm_parse_elf(const char *path, const char *fname, pj *symbols, pj *cfgs) {
    size_t n;
    uint8_t *d = pw_slurp(path, &n);
    if (d == nullptr) pw_die("FileNotFoundError: [Errno %d] %s: '%s'", errno, strerror(errno), path);
    if (n < 52 || memcmp(d, "\x7f" "ELF", 4) != 0) pw_die("ValueError: %s is not a valid ELF file", path);
    const unsigned ei_class = d[4], ei_data = d[5];
    elf_in e = { d, n, ei_data == 1, path };
    const bool is64 = ei_class == 2;
    uint64_t e_type, e_machine, e_entry, e_shoff, e_shentsize, e_shnum, e_shstrndx;
    e_type = rd(&e, 16, 2);
    e_machine = rd(&e, 18, 2);
    if (is64) {
        e_entry = rd(&e, 24, 8);
        e_shoff = rd(&e, 40, 8);
        (void)rd(&e, 63, 1);  /* the 64-byte ELF64 header must be present */
        e_shentsize = rd(&e, 58, 2);
        e_shnum = rd(&e, 60, 2);
        e_shstrndx = rd(&e, 62, 2);
    } else {
        e_entry = rd(&e, 24, 4);
        e_shoff = rd(&e, 32, 4);
        e_shentsize = rd(&e, 46, 2);
        e_shnum = rd(&e, 48, 2);
        e_shstrndx = rd(&e, 50, 2);
    }
    elf_sec *secs = calloc(e_shnum ? e_shnum : 1, sizeof *secs);
    if (secs == nullptr) abort();
    for (uint64_t i = 0; i < e_shnum; i++) {
        const uint64_t o = e_shoff + i * e_shentsize;
        elf_sec *s = &secs[i];
        if (is64) {
            s->name_off = (uint32_t)rd(&e, o, 4);
            s->type = (uint32_t)rd(&e, o + 4, 4);
            s->flags = rd(&e, o + 8, 8);
            s->addr = rd(&e, o + 16, 8);
            s->offset = rd(&e, o + 24, 8);
            s->size = rd(&e, o + 32, 8);
            s->link = (uint32_t)rd(&e, o + 40, 4);
            s->entsize = rd(&e, o + 56, 8);
        } else {
            s->name_off = (uint32_t)rd(&e, o, 4);
            s->type = (uint32_t)rd(&e, o + 4, 4);
            s->flags = rd(&e, o + 8, 4);
            s->addr = rd(&e, o + 12, 4);
            s->offset = rd(&e, o + 16, 4);
            s->size = rd(&e, o + 20, 4);
            s->link = (uint32_t)rd(&e, o + 24, 4);
            s->entsize = rd(&e, o + 36, 4);
        }
    }
    const uint8_t *shstr = d;
    size_t shstr_n = 0;
    if (e_shstrndx < e_shnum) slice(&e, secs[e_shstrndx].offset, secs[e_shstrndx].size, &shstr, &shstr_n);
    for (uint64_t i = 0; i < e_shnum; i++) secs[i].name = read_cstr(shstr, shstr_n, secs[i].name_off);

    elf_sym *all = nullptr;
    size_t nall = 0;
    for (uint64_t si = 0; si < e_shnum; si++) {
        const elf_sec *s = &secs[si];
        if ((s->type != 2 && s->type != 11) || s->entsize == 0) continue;
        const uint8_t *str = d;
        size_t str_n = 0;
        if (s->link < e_shnum) slice(&e, secs[s->link].offset, secs[s->link].size, &str, &str_n);
        const uint64_t count = s->size / s->entsize;
        for (uint64_t k = 0; k < count; k++) {
            const uint64_t o = s->offset + k * s->entsize;
            uint64_t st_name, st_info, st_shndx, st_value, st_size;
            if (is64) {
                if (o + 24 > n) short_read(&e, (size_t)(o + 24));
                st_name = rd(&e, o, 4);
                st_info = rd(&e, o + 4, 1);
                st_shndx = rd(&e, o + 6, 2);
                st_value = rd(&e, o + 8, 8);
                st_size = rd(&e, o + 16, 8);
            } else {
                if (o + 16 > n) short_read(&e, (size_t)(o + 16));
                st_name = rd(&e, o, 4);
                st_value = rd(&e, o + 4, 4);
                st_size = rd(&e, o + 8, 4);
                st_info = rd(&e, o + 12, 1);
                st_shndx = rd(&e, o + 14, 2);
            }
            char *nm = read_cstr(str, str_n, st_name);
            if (!nm[0]) { free(nm); continue; }
            const char *sec_name = st_shndx < e_shnum ? secs[st_shndx].name : "ABS";
            pj *sy = pj_obj();
            pj_set(sy, "name", pj_str(nm));
            pj_set(sy, "source_kind", pj_str("elf"));
            pj_set(sy, "source_file", pj_str(fname));
            pj_set(sy, "sym_type", pj_str(stt_name((unsigned)(st_info & 0xF))));
            pj_set(sy, "binding", pj_str(stb_name((unsigned)(st_info >> 4))));
            pj_set(sy, "address", pj_uint(st_value));
            pj_set(sy, "size", pj_uint(st_size));
            pj_set(sy, "section", pj_str(sec_name));
            pj_push(symbols, sy);
            elf_sym *na = realloc(all, sizeof *all * (nall + 1));
            if (na == nullptr) abort();
            all = na;
            all[nall++] = (elf_sym){ nm, st_value, st_size, (uint32_t)st_shndx, (unsigned)(st_info & 0xF) };
        }
    }
#ifdef PW_BSM_X86
    if (is64 && ei_data == 1 && e_machine == 0x3E) x86_cfgs(&e, secs, e_shnum, all, nall, fname, cfgs);
#else
    (void)cfgs;
#endif
    pj *hdr = pj_obj();
    pj_set(hdr, "file", pj_str(fname));
    pj_set(hdr, "class", pj_str(is64 ? "ELF64" : "ELF32"));
    pj_set(hdr, "endian", pj_str(ei_data == 1 ? "little" : "big"));
    static const char *const types[] = { nullptr, "ET_REL", "ET_EXEC", "ET_DYN", "ET_CORE" };
    pj_set(hdr, "type", (e_type >= 1 && e_type <= 4) ? pj_str(types[e_type]) : hex_str(e_type));
    const char *mach = e_machine == 0x03 ? "x86" : e_machine == 0x28 ? "ARM" : e_machine == 0x3E ? "x86-64"
                     : e_machine == 0xB7 ? "AArch64" : e_machine == 0xF3 ? "RISC-V" : nullptr;
    pj_set(hdr, "machine", mach ? pj_str(mach) : hex_str(e_machine));
    pj_set(hdr, "entry_point", hex_str(e_entry));
    pj *sl = pj_arr();
    for (uint64_t i = 0; i < e_shnum; i++) {
        if (!secs[i].name[0]) continue;
        pj *so = pj_obj();
        pj_set(so, "name", pj_str(secs[i].name));
        pj_set(so, "addr", hex_str(secs[i].addr));
        pj_set(so, "size", pj_uint(secs[i].size));
        pj_push(sl, so);
    }
    pj_set(hdr, "sections", sl);
    for (size_t i = 0; i < nall; i++) free(all[i].name);
    free(all);
    for (uint64_t i = 0; i < e_shnum; i++) free(secs[i].name);
    free(secs);
    free(d);
    return hdr;
}
