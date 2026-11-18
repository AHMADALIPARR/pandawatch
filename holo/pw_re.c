/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Backtracking matcher with explicit continuations. C23. */
#include "pw_re.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { N_CHAR, N_ANY, N_SET, N_BOL, N_EOL, N_WB, N_NWB, N_GROUP, N_SEQ, N_ALT, N_REP } ntype;

typedef struct node node;
struct node {
    ntype t;
    unsigned char c;
    uint8_t set[32];
    int cap;          /* N_GROUP: capture index, -1 for (?:) */
    int min, max;     /* N_REP: max -1 = unbounded */
    bool greedy;
    node **kids;
    int nk;
};

struct pw_re {
    node *root;
    int flags;
    int ncap;
};

typedef struct {
    const char *p;
    const char *pat;
    int flags;
    int ncap;
} parser;

[[noreturn]] static void bad(const parser *ps, const char *why) {
    fprintf(stderr, "pw_re: %s in pattern \"%s\" at %ld\n", why, ps->pat, (long)(ps->p - ps->pat));
    abort();
}

static node *mk(ntype t) {
    node *n = calloc(1, sizeof *n);
    if (n == nullptr) abort();
    n->t = t;
    n->cap = -1;
    return n;
}

static void add_kid(node *n, node *k) {
    node **v = realloc(n->kids, sizeof *v * (size_t)(n->nk + 1));
    if (v == nullptr) abort();
    n->kids = v;
    n->kids[n->nk++] = k;
}

static void set_add(uint8_t *set, unsigned c) { set[c >> 3] |= (uint8_t)(1u << (c & 7)); }
static bool set_has(const uint8_t *set, unsigned c) { return (set[c >> 3] >> (c & 7)) & 1; }

static bool is_word(unsigned c) {
    return c >= 0x80 || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
static bool is_space(unsigned c) { return c == ' ' || (c >= 9 && c <= 13) || (c >= 0x1c && c <= 0x1f); }
static bool is_digit(unsigned c) { return c >= '0' && c <= '9'; }

static void set_class(uint8_t *set, char cls) {
    for (unsigned c = 0; c < 256; c++) {
        bool in = false;
        switch (cls) {
        case 'd': in = is_digit(c); break;
        case 'D': in = !is_digit(c); break;
        case 'w': in = is_word(c); break;
        case 'W': in = !is_word(c); break;
        case 's': in = is_space(c); break;
        case 'S': in = !is_space(c); break;
        default: break;
        }
        if (in) set_add(set, c);
    }
}

static unsigned esc_char(char c) {
    switch (c) {
    case 'n': return '\n';
    case 't': return '\t';
    case 'r': return '\r';
    case 'f': return '\f';
    case 'v': return '\v';
    case '0': return 0;
    default: return (unsigned char)c;
    }
}

static node *parse_alt(parser *ps);

static node *parse_set(parser *ps) {
    node *n = mk(N_SET);
    bool neg = false;
    if (*ps->p == '^') { neg = true; ps->p++; }
    uint8_t set[32] = {0};
    bool first = true;
    while (*ps->p && (*ps->p != ']' || first)) {
        first = false;
        unsigned lo;
        if (*ps->p == '\\') {
            ps->p++;
            char e = *ps->p++;
            if (strchr("dDwWsS", e) && e) { set_class(set, e); continue; }
            lo = esc_char(e);
        } else {
            lo = (unsigned char)*ps->p++;
        }
        if (ps->p[0] == '-' && ps->p[1] && ps->p[1] != ']') {
            ps->p++;
            unsigned hi;
            if (*ps->p == '\\') { ps->p++; hi = esc_char(*ps->p++); }
            else hi = (unsigned char)*ps->p++;
            for (unsigned c = lo; c <= hi; c++) set_add(set, c);
        } else {
            set_add(set, lo);
        }
    }
    if (*ps->p != ']') bad(ps, "unterminated class");
    ps->p++;
    if (ps->flags & PW_RE_I) {
        for (unsigned c = 'a'; c <= 'z'; c++) {
            if (set_has(set, c) || set_has(set, c - 32)) { set_add(set, c); set_add(set, c - 32); }
        }
    }
    for (unsigned c = 0; c < 256; c++) {
        if (set_has(set, c) != neg) set_add(n->set, c);
    }
    return n;
}

static bool parse_int(parser *ps, int *out) {
    if (!is_digit((unsigned char)*ps->p)) return false;
    int v = 0;
    while (is_digit((unsigned char)*ps->p)) v = v * 10 + (*ps->p++ - '0');
    *out = v;
    return true;
}

static node *parse_atom(parser *ps) {
    char c = *ps->p++;
    switch (c) {
    case '(': {
        node *g = mk(N_GROUP);
        if (ps->p[0] == '?' && ps->p[1] == ':') {
            ps->p += 2;
        } else {
            if (ps->ncap >= PW_RE_MAXCAP - 1) bad(ps, "too many groups");
            g->cap = ++ps->ncap;
        }
        add_kid(g, parse_alt(ps));
        if (*ps->p != ')') bad(ps, "missing )");
        ps->p++;
        return g;
    }
    case '[': return parse_set(ps);
    case '.': {
        node *n = mk(N_ANY);
        return n;
    }
    case '^': return mk(N_BOL);
    case '$': return mk(N_EOL);
    case '\\': {
        char e = *ps->p++;
        if (e == 'b') return mk(N_WB);
        if (e == 'B') return mk(N_NWB);
        if (e && strchr("dDwWsS", e)) {
            node *n = mk(N_SET);
            set_class(n->set, e);
            return n;
        }
        if (!e) bad(ps, "trailing backslash");
        node *n = mk(N_CHAR);
        n->c = (unsigned char)esc_char(e);
        return n;
    }
    default: {
        node *n = mk(N_CHAR);
        n->c = (unsigned char)c;
        return n;
    }
    }
}

static node *parse_seq(parser *ps) {
    node *seq = mk(N_SEQ);
    while (*ps->p && *ps->p != '|' && *ps->p != ')') {
        node *a = parse_atom(ps);
        for (;;) {
            int mn, mx;
            const char *save = ps->p;
            if (*ps->p == '*') { mn = 0; mx = -1; ps->p++; }
            else if (*ps->p == '+') { mn = 1; mx = -1; ps->p++; }
            else if (*ps->p == '?') { mn = 0; mx = 1; ps->p++; }
            else if (*ps->p == '{') {
                ps->p++;
                if (!parse_int(ps, &mn)) { ps->p = save; break; }
                mx = mn;
                if (*ps->p == ',') {
                    ps->p++;
                    if (!parse_int(ps, &mx)) mx = -1;
                }
                if (*ps->p != '}') { ps->p = save; break; }
                ps->p++;
            } else break;
            node *r = mk(N_REP);
            r->min = mn;
            r->max = mx;
            r->greedy = true;
            if (*ps->p == '?') { r->greedy = false; ps->p++; }
            add_kid(r, a);
            a = r;
        }
        add_kid(seq, a);
    }
    return seq;
}

static node *parse_alt(parser *ps) {
    node *first = parse_seq(ps);
    if (*ps->p != '|') return first;
    node *alt = mk(N_ALT);
    add_kid(alt, first);
    while (*ps->p == '|') {
        ps->p++;
        add_kid(alt, parse_seq(ps));
    }
    return alt;
}

pw_re *pw_re_compile(const char *pattern, int flags) {
    parser ps = { pattern, pattern, flags, 0 };
    node *root = parse_alt(&ps);
    if (*ps.p) bad(&ps, "unbalanced )");
    pw_re *re = calloc(1, sizeof *re);
    if (re == nullptr) abort();
    re->root = root;
    re->flags = flags;
    re->ncap = ps.ncap;
    return re;
}

static void free_node(node *n) {
    if (n == nullptr) return;
    for (int i = 0; i < n->nk; i++) free_node(n->kids[i]);
    free(n->kids);
    free(n);
}

void pw_re_free(pw_re *re) {
    if (re == nullptr) return;
    free_node(re->root);
    free(re);
}

/* ---- matcher ---- */

typedef struct {
    const unsigned char *s;
    size_t len;
    int flags;
    long so[PW_RE_MAXCAP], eo[PW_RE_MAXCAP];
    size_t end;
} mstate;

typedef struct kont kont;
struct kont {
    bool (*fn)(mstate *, const kont *, size_t);
    const node *n;
    int i;
    size_t p0;
    const kont *next;
};

static bool m_node(mstate *m, const node *n, size_t pos, const kont *k);

static unsigned fold(unsigned c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

static bool atom_ok(const mstate *m, const node *n, size_t pos) {
    if (pos >= m->len) return false;
    unsigned c = m->s[pos];
    switch (n->t) {
    case N_CHAR: return (m->flags & PW_RE_I) ? fold(c) == fold(n->c) : c == n->c;
    case N_ANY: return (m->flags & PW_RE_S) || c != '\n';
    case N_SET: return set_has(n->set, c);
    default: return false;
    }
}

static bool is_single(const node *n) { return n->t == N_CHAR || n->t == N_ANY || n->t == N_SET; }

static bool seq_from(mstate *m, const node *n, int i, size_t pos, const kont *k);
static bool k_seq(mstate *m, const kont *k, size_t pos) { return seq_from(m, k->n, k->i, pos, k->next); }

static bool seq_from(mstate *m, const node *n, int i, size_t pos, const kont *k) {
    if (i == n->nk) return k->fn(m, k, pos);
    const kont k2 = { k_seq, n, i + 1, 0, k };
    return m_node(m, n->kids[i], pos, &k2);
}

static bool k_group(mstate *m, const kont *k, size_t pos) {
    const int cap = k->n->cap;
    const long oso = m->so[cap], oeo = m->eo[cap];
    m->so[cap] = (long)k->p0;
    m->eo[cap] = (long)pos;
    if (k->next->fn(m, k->next, pos)) return true;
    m->so[cap] = oso;
    m->eo[cap] = oeo;
    return false;
}

static bool rep(mstate *m, const node *n, int cnt, size_t pos, const kont *k);
static bool k_rep(mstate *m, const kont *k, size_t pos) {
    if (pos == k->p0 && k->i > k->n->min) return false;  /* empty iteration */
    return rep(m, k->n, k->i, pos, k->next);
}

static bool rep(mstate *m, const node *n, int cnt, size_t pos, const kont *k) {
    const bool more = n->max < 0 || cnt < n->max;
    if (n->greedy) {
        if (more) {
            const kont k2 = { k_rep, n, cnt + 1, pos, k };
            if (m_node(m, n->kids[0], pos, &k2)) return true;
        }
        return cnt >= n->min && k->fn(m, k, pos);
    }
    if (cnt >= n->min && k->fn(m, k, pos)) return true;
    if (more) {
        const kont k2 = { k_rep, n, cnt + 1, pos, k };
        return m_node(m, n->kids[0], pos, &k2);
    }
    return false;
}

static bool m_node(mstate *m, const node *n, size_t pos, const kont *k) {
    switch (n->t) {
    case N_CHAR: case N_ANY: case N_SET:
        return atom_ok(m, n, pos) && k->fn(m, k, pos + 1);
    case N_BOL:
        if (pos == 0 || ((m->flags & PW_RE_M) && m->s[pos - 1] == '\n')) return k->fn(m, k, pos);
        return false;
    case N_EOL:
        if (pos == m->len || (m->s[pos] == '\n' && ((m->flags & PW_RE_M) || pos + 1 == m->len)))
            return k->fn(m, k, pos);
        return false;
    case N_WB: case N_NWB: {
        const bool a = pos > 0 && is_word(m->s[pos - 1]);
        const bool b = pos < m->len && is_word(m->s[pos]);
        if ((a != b) == (n->t == N_WB)) return k->fn(m, k, pos);
        return false;
    }
    case N_GROUP:
        if (n->cap < 0) return m_node(m, n->kids[0], pos, k);
        {
            const kont k2 = { k_group, n, 0, pos, k };
            return m_node(m, n->kids[0], pos, &k2);
        }
    case N_SEQ:
        return seq_from(m, n, 0, pos, k);
    case N_ALT:
        for (int i = 0; i < n->nk; i++) {
            if (m_node(m, n->kids[i], pos, k)) return true;
        }
        return false;
    case N_REP:
        if (is_single(n->kids[0])) {
            const node *a = n->kids[0];
            size_t run = 0;
            const size_t cap = n->max < 0 ? SIZE_MAX : (size_t)n->max;
            if (n->greedy) {
                while (run < cap && atom_ok(m, a, pos + run)) run++;
                if (run < (size_t)n->min) return false;
                for (size_t j = run + 1; j-- > (size_t)n->min;) {
                    if (k->fn(m, k, pos + j)) return true;
                }
                return false;
            }
            while (run < (size_t)n->min) {
                if (!atom_ok(m, a, pos + run)) return false;
                run++;
            }
            for (;;) {
                if (k->fn(m, k, pos + run)) return true;
                if (run >= cap || !atom_ok(m, a, pos + run)) return false;
                run++;
            }
        }
        return rep(m, n, 0, pos, k);
    }
    return false;
}

static bool k_done(mstate *m, const kont *k, size_t pos) {
    (void)k;
    m->end = pos;
    return true;
}

bool pw_re_match_at(const pw_re *re, const char *s, size_t len, size_t pos, pw_rm *out) {
    mstate m;
    m.s = (const unsigned char *)s;
    m.len = len;
    m.flags = re->flags;
    for (int i = 0; i < PW_RE_MAXCAP; i++) m.so[i] = m.eo[i] = -1;
    const kont done = { k_done, nullptr, 0, 0, nullptr };
    if (!m_node(&m, re->root, pos, &done)) return false;
    if (out) {
        for (int i = 0; i < PW_RE_MAXCAP; i++) { out->so[i] = m.so[i]; out->eo[i] = m.eo[i]; }
        out->so[0] = (long)pos;
        out->eo[0] = (long)m.end;
    }
    return true;
}

bool pw_re_search(const pw_re *re, const char *s, size_t len, size_t pos, pw_rm *out) {
    for (size_t p = pos; p <= len; p++) {
        if (pw_re_match_at(re, s, len, p, out)) return true;
    }
    return false;
}

bool pw_re_next(const pw_re *re, const char *s, size_t len, size_t *pos, pw_rm *m) {
    if (*pos > len) return false;
    if (!pw_re_search(re, s, len, *pos, m)) { *pos = len + 1; return false; }
    *pos = (size_t)m->eo[0] > (size_t)m->so[0] ? (size_t)m->eo[0] : (size_t)m->eo[0] + 1;
    return true;
}

char *pw_re_sub_lit(const pw_re *re, const char *s, size_t len, const char *repl, size_t *out_len) {
    const size_t rl = strlen(repl);
    size_t cap = len + 1, n = 0;
    char *o = malloc(cap);
    if (o == nullptr) abort();
    size_t p = 0, copied = 0;
    pw_rm m;
    while (p <= len && pw_re_search(re, s, len, p, &m)) {
        const size_t so = (size_t)m.so[0], eo = (size_t)m.eo[0];
        const size_t need = n + (so - copied) + rl + 1;
        if (need > cap) { cap = need * 2; o = realloc(o, cap); if (o == nullptr) abort(); }
        memcpy(o + n, s + copied, so - copied);
        n += so - copied;
        memcpy(o + n, repl, rl);
        n += rl;
        copied = eo;
        if (eo == so) {
            if (eo < len) {
                if (n + 2 > cap) { cap = (n + 2) * 2; o = realloc(o, cap); if (o == nullptr) abort(); }
                o[n++] = s[eo];
            }
            copied = eo + 1;
            p = eo + 1;
        } else {
            p = eo;
        }
    }
    if (copied < len) {
        if (n + (len - copied) + 1 > cap) { cap = n + (len - copied) + 1; o = realloc(o, cap); if (o == nullptr) abort(); }
        memcpy(o + n, s + copied, len - copied);
        n += len - copied;
    }
    o[n] = 0;
    if (out_len) *out_len = n;
    return o;
}

char *pw_re_sub_empty(const pw_re *re, const char *s, size_t len, size_t *out_len) {
    return pw_re_sub_lit(re, s, len, "", out_len);
}

bool pw_rm_set(const pw_rm *m, int g) { return m->so[g] >= 0; }

char *pw_rm_dup(const pw_rm *m, int g, const char *s) {
    if (m->so[g] < 0) return nullptr;
    const size_t n = (size_t)(m->eo[g] - m->so[g]);
    char *o = malloc(n + 1);
    if (o == nullptr) abort();
    memcpy(o, s + m->so[g], n);
    o[n] = 0;
    return o;
}
