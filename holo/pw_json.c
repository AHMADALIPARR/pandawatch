/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* JSON writer and reader with Python json module output. C23. */
#include "pw_json.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pw_text.h"

static pj *mk(pj_type t) {
    pj *v = calloc(1, sizeof *v);
    if (v == nullptr) abort();
    v->t = t;
    return v;
}

pj *pj_null(void) { return mk(PJ_NULL); }
pj *pj_bool(bool b) { pj *v = mk(PJ_BOOL); v->b = b; return v; }
pj *pj_int(int64_t i) { pj *v = mk(PJ_INT); v->i = i; return v; }
pj *pj_uint(uint64_t u) {
    if (u <= (uint64_t)INT64_MAX) return pj_int((int64_t)u);
    pj *v = mk(PJ_UINT);
    v->u = u;
    return v;
}
pj *pj_strn(const char *s, size_t n) {
    pj *v = mk(PJ_STR);
    v->s = pw_dupn(s, n);
    v->slen = n;
    return v;
}
pj *pj_strown(char *s) {
    pj *v = mk(PJ_STR);
    v->s = s;
    v->slen = strlen(s);
    return v;
}
pj *pj_str(const char *s) { return s ? pj_strn(s, strlen(s)) : pj_null(); }
pj *pj_arr(void) { return mk(PJ_ARR); }
pj *pj_obj(void) { return mk(PJ_OBJ); }

pj *pj_copy(const pj *v) {
    if (v == nullptr) return pj_null();
    pj *c = mk(v->t);
    c->b = v->b; c->i = v->i; c->u = v->u; c->d = v->d;
    if (v->t == PJ_STR) { c->s = pw_dupn(v->s, v->slen); c->slen = v->slen; }
    for (size_t i = 0; i < v->n; i++) {
        if (v->t == PJ_OBJ) pj_set(c, v->k[i], pj_copy(v->v[i]));
        else pj_push(c, pj_copy(v->v[i]));
    }
    return c;
}

void pj_free(pj *v) {
    if (v == nullptr) return;
    for (size_t i = 0; i < v->n; i++) {
        pj_free(v->v[i]);
        if (v->k) free(v->k[i]);
    }
    free(v->v);
    free(v->k);
    free(v->s);
    free(v);
}

static void grow(pj *c) {
    if (c->n < c->cap) return;
    c->cap = c->cap ? c->cap * 2 : 8;
    c->v = realloc(c->v, sizeof *c->v * c->cap);
    if (c->v == nullptr) abort();
    if (c->t == PJ_OBJ) {
        c->k = realloc(c->k, sizeof *c->k * c->cap);
        if (c->k == nullptr) abort();
    }
}

void pj_push(pj *arr, pj *v) {
    grow(arr);
    arr->v[arr->n++] = v;
}

void pj_set(pj *obj, const char *key, pj *v) {
    for (size_t i = 0; i < obj->n; i++) {
        if (strcmp(obj->k[i], key) == 0) {
            pj_free(obj->v[i]);
            obj->v[i] = v;
            return;
        }
    }
    grow(obj);
    obj->k[obj->n] = pw_dup(key);
    obj->v[obj->n++] = v;
}

pj *pj_get(const pj *obj, const char *key) {
    if (obj == nullptr || obj->t != PJ_OBJ) return nullptr;
    for (size_t i = 0; i < obj->n; i++) {
        if (strcmp(obj->k[i], key) == 0) return obj->v[i];
    }
    return nullptr;
}

int64_t pj_as_int(const pj *v) {
    if (v == nullptr) return 0;
    switch (v->t) {
    case PJ_INT: return v->i;
    case PJ_UINT: return (int64_t)v->u;
    case PJ_BOOL: return v->b;
    case PJ_FLOAT: return (int64_t)v->d;
    case PJ_STR: return strtoll(v->s, nullptr, 10);
    default: return 0;
    }
}

const char *pj_as_str(const pj *v) { return (v && v->t == PJ_STR) ? v->s : ""; }

bool pj_truthy(const pj *v) {
    if (v == nullptr) return false;
    switch (v->t) {
    case PJ_NULL: return false;
    case PJ_BOOL: return v->b;
    case PJ_INT: return v->i != 0;
    case PJ_UINT: return true;
    case PJ_FLOAT: return v->d != 0.0;
    case PJ_STR: return v->slen != 0;
    default: return v->n != 0;
    }
}

/* ---- writer ---- */

/* Decodes one code point; invalid bytes give U+FFFD and advance one byte.
 * Encoded surrogates (ED A0..BF xx) decode to the surrogate value. */
static uint32_t utf8_next(const unsigned char *s, size_t n, size_t *i) {
    const unsigned c = s[*i];
    if (c < 0x80) { (*i)++; return c; }
    int need;
    uint32_t cp;
    if (c >= 0xC2 && c <= 0xDF) { need = 1; cp = c & 0x1F; }
    else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0F; }
    else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07; }
    else { (*i)++; return 0xFFFD; }
    for (int k = 1; k <= need; k++) {
        if (*i + (size_t)k >= n || (s[*i + (size_t)k] & 0xC0) != 0x80) { (*i)++; return 0xFFFD; }
        cp = (cp << 6) | (s[*i + (size_t)k] & 0x3F);
    }
    if ((need == 2 && cp < 0x800) || (need == 3 && (cp < 0x10000 || cp > 0x10FFFF))) { (*i)++; return 0xFFFD; }
    *i += (size_t)need + 1;
    return cp;
}

static void put_str(pw_buf *b, const char *s, size_t n) {
    pw_buf_putc(b, '"');
    const unsigned char *u = (const unsigned char *)s;
    size_t i = 0;
    while (i < n) {
        const uint32_t cp = utf8_next(u, n, &i);
        switch (cp) {
        case '"': pw_buf_puts(b, "\\\""); continue;
        case '\\': pw_buf_puts(b, "\\\\"); continue;
        case '\n': pw_buf_puts(b, "\\n"); continue;
        case '\r': pw_buf_puts(b, "\\r"); continue;
        case '\t': pw_buf_puts(b, "\\t"); continue;
        case '\b': pw_buf_puts(b, "\\b"); continue;
        case '\f': pw_buf_puts(b, "\\f"); continue;
        default: break;
        }
        if (cp >= 0x20 && cp <= 0x7E) {
            pw_buf_putc(b, (int)cp);
        } else if (cp < 0x10000) {
            pw_buf_printf(b, "\\u%04" PRIx32, cp);
        } else {
            const uint32_t v = cp - 0x10000;
            pw_buf_printf(b, "\\u%04" PRIx32 "\\u%04" PRIx32, 0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF));
        }
    }
    pw_buf_putc(b, '"');
}

/* float.__repr__ */
static void put_float(pw_buf *b, double d) {
    if (isnan(d)) { pw_buf_puts(b, "NaN"); return; }
    if (isinf(d)) { pw_buf_puts(b, d > 0 ? "Infinity" : "-Infinity"); return; }
    char tmp[64];
    int prec = 1;
    for (; prec <= 17; prec++) {
        snprintf(tmp, sizeof tmp, "%.*e", prec - 1, d);
        if (strtod(tmp, nullptr) == d) break;
    }
    /* tmp = [-]D.DDDDe[+-]XX */
    const bool neg = tmp[0] == '-';
    const char *p = tmp + neg;
    char digits[32];
    size_t nd = 0;
    for (; *p && *p != 'e'; p++) {
        if (*p != '.') digits[nd++] = *p;
    }
    while (nd > 1 && digits[nd - 1] == '0') nd--;
    digits[nd] = 0;
    const int exp10 = atoi(p + 1);
    if (neg) pw_buf_putc(b, '-');
    if (exp10 < -4 || exp10 >= 16) {
        pw_buf_putc(b, digits[0]);
        if (nd > 1) { pw_buf_putc(b, '.'); pw_buf_puts(b, digits + 1); }
        pw_buf_printf(b, "e%c%02d", exp10 < 0 ? '-' : '+', exp10 < 0 ? -exp10 : exp10);
    } else if (exp10 < 0) {
        pw_buf_puts(b, "0.");
        for (int z = 0; z < -exp10 - 1; z++) pw_buf_putc(b, '0');
        pw_buf_puts(b, digits);
    } else {
        for (int k = 0; k <= exp10; k++) pw_buf_putc(b, (size_t)k < nd ? digits[k] : '0');
        pw_buf_putc(b, '.');
        if ((size_t)exp10 + 1 < nd) pw_buf_puts(b, digits + exp10 + 1);
        else pw_buf_putc(b, '0');
    }
}

static int cmp_keys(const void *a, const void *b) {
    return strcmp(**(char *const *const *)a, **(char *const *const *)b);
}

static void newline(pw_buf *b, int indent, int level) {
    pw_buf_putc(b, '\n');
    for (int i = 0; i < indent * level; i++) pw_buf_putc(b, ' ');
}

static void dump(pw_buf *b, const pj *v, int indent, bool sort_keys, int level) {
    switch (v->t) {
    case PJ_NULL: pw_buf_puts(b, "null"); return;
    case PJ_BOOL: pw_buf_puts(b, v->b ? "true" : "false"); return;
    case PJ_INT: pw_buf_printf(b, "%" PRId64, v->i); return;
    case PJ_UINT: pw_buf_printf(b, "%" PRIu64, v->u); return;
    case PJ_FLOAT: put_float(b, v->d); return;
    case PJ_STR: put_str(b, v->s, v->slen); return;
    case PJ_ARR:
        if (v->n == 0) { pw_buf_puts(b, "[]"); return; }
        pw_buf_putc(b, '[');
        for (size_t i = 0; i < v->n; i++) {
            if (i) pw_buf_putc(b, ',');
            if (indent >= 0) newline(b, indent, level + 1);
            dump(b, v->v[i], indent, sort_keys, level + 1);
        }
        if (indent >= 0) newline(b, indent, level);
        pw_buf_putc(b, ']');
        return;
    case PJ_OBJ: {
        if (v->n == 0) { pw_buf_puts(b, "{}"); return; }
        size_t *order = malloc(sizeof *order * v->n);
        char ***keys = malloc(sizeof *keys * v->n);
        if (order == nullptr || keys == nullptr) abort();
        for (size_t i = 0; i < v->n; i++) keys[i] = &v->k[i];
        if (sort_keys) qsort(keys, v->n, sizeof *keys, cmp_keys);
        for (size_t i = 0; i < v->n; i++) order[i] = (size_t)(keys[i] - v->k);
        pw_buf_putc(b, '{');
        for (size_t j = 0; j < v->n; j++) {
            const size_t i = order[j];
            if (j) pw_buf_putc(b, ',');
            if (indent >= 0) newline(b, indent, level + 1);
            put_str(b, v->k[i], strlen(v->k[i]));
            pw_buf_puts(b, indent >= 0 ? ": " : ":");
            dump(b, v->v[i], indent, sort_keys, level + 1);
        }
        if (indent >= 0) newline(b, indent, level);
        pw_buf_putc(b, '}');
        free(order);
        free(keys);
        return;
    }
    }
}

char *pj_dump(const pj *v, int indent, bool sort_keys, size_t *len) {
    pw_buf b = {0};
    dump(&b, v, indent, sort_keys, 0);
    return pw_buf_take(&b, len);
}

/* repr(str): single quotes unless the text has ' and no ". Non-printable
 * ASCII is escaped; printable non-ASCII is kept. */
static void repr_str(pw_buf *b, const char *s, size_t n) {
    const bool sq = memchr(s, '\'', n) != nullptr, dq = memchr(s, '"', n) != nullptr;
    const char q = (sq && !dq) ? '"' : '\'';
    pw_buf_putc(b, q);
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = (unsigned char)s[i];
        if (c == (unsigned char)q || c == '\\') { pw_buf_putc(b, '\\'); pw_buf_putc(b, c); }
        else if (c == '\n') pw_buf_puts(b, "\\n");
        else if (c == '\r') pw_buf_puts(b, "\\r");
        else if (c == '\t') pw_buf_puts(b, "\\t");
        else if (c < 0x20 || c == 0x7F) pw_buf_printf(b, "\\x%02x", c);
        else pw_buf_putc(b, c);
    }
    pw_buf_putc(b, q);
}

static void repr(pw_buf *b, const pj *v) {
    switch (v->t) {
    case PJ_NULL: pw_buf_puts(b, "None"); return;
    case PJ_BOOL: pw_buf_puts(b, v->b ? "True" : "False"); return;
    case PJ_INT: pw_buf_printf(b, "%" PRId64, v->i); return;
    case PJ_UINT: pw_buf_printf(b, "%" PRIu64, v->u); return;
    case PJ_FLOAT:
        if (isnan(v->d)) pw_buf_puts(b, "nan");
        else if (isinf(v->d)) pw_buf_puts(b, v->d > 0 ? "inf" : "-inf");
        else put_float(b, v->d);
        return;
    case PJ_STR: repr_str(b, v->s, v->slen); return;
    case PJ_ARR:
        pw_buf_putc(b, '[');
        for (size_t i = 0; i < v->n; i++) {
            if (i) pw_buf_puts(b, ", ");
            repr(b, v->v[i]);
        }
        pw_buf_putc(b, ']');
        return;
    case PJ_OBJ:
        pw_buf_putc(b, '{');
        for (size_t i = 0; i < v->n; i++) {
            if (i) pw_buf_puts(b, ", ");
            repr_str(b, v->k[i], strlen(v->k[i]));
            pw_buf_puts(b, ": ");
            repr(b, v->v[i]);
        }
        pw_buf_putc(b, '}');
        return;
    }
}

char *pj_pyrepr(const pj *v) {
    pw_buf b = {0};
    if (v == nullptr) pw_buf_puts(&b, "None");
    else repr(&b, v);
    return pw_buf_take(&b, nullptr);
}

/* ---- reader ---- */

typedef struct {
    const char *s;
    size_t n, i;
    char *err;
    size_t errcap;
    bool failed;
} rd;

static void fail(rd *r, const char *msg) {
    if (r->failed) return;
    r->failed = true;
    size_t line = 1, col = 1;
    for (size_t k = 0; k < r->i && k < r->n; k++) {
        if (r->s[k] == '\n') { line++; col = 1; } else col++;
    }
    if (r->err) snprintf(r->err, r->errcap, "%s: line %zu column %zu (char %zu)", msg, line, col, r->i);
}

static void ws(rd *r) {
    while (r->i < r->n && (r->s[r->i] == ' ' || r->s[r->i] == '\t' || r->s[r->i] == '\n' || r->s[r->i] == '\r')) r->i++;
}

static void put_utf8(pw_buf *b, uint32_t cp) {
    if (cp < 0x80) pw_buf_putc(b, (int)cp);
    else if (cp < 0x800) { pw_buf_putc(b, (int)(0xC0 | (cp >> 6))); pw_buf_putc(b, (int)(0x80 | (cp & 0x3F))); }
    else if (cp < 0x10000) {
        pw_buf_putc(b, (int)(0xE0 | (cp >> 12)));
        pw_buf_putc(b, (int)(0x80 | ((cp >> 6) & 0x3F)));
        pw_buf_putc(b, (int)(0x80 | (cp & 0x3F)));
    } else {
        pw_buf_putc(b, (int)(0xF0 | (cp >> 18)));
        pw_buf_putc(b, (int)(0x80 | ((cp >> 12) & 0x3F)));
        pw_buf_putc(b, (int)(0x80 | ((cp >> 6) & 0x3F)));
        pw_buf_putc(b, (int)(0x80 | (cp & 0x3F)));
    }
}

static int hex4(rd *r, size_t at, uint32_t *out) {
    if (at + 4 > r->n) return -1;
    uint32_t v = 0;
    for (size_t k = 0; k < 4; k++) {
        const char c = r->s[at + k];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static char *read_string(rd *r, size_t *len) {
    pw_buf b = {0};
    pw_buf_put(&b, "", 0);
    r->i++;  /* opening quote */
    for (;;) {
        if (r->i >= r->n) { fail(r, "Unterminated string starting at"); free(b.p); return nullptr; }
        const unsigned char c = (unsigned char)r->s[r->i];
        if (c == '"') { r->i++; break; }
        if (c < 0x20) { fail(r, "Invalid control character at"); free(b.p); return nullptr; }
        if (c != '\\') { pw_buf_putc(&b, c); r->i++; continue; }
        if (r->i + 1 >= r->n) { fail(r, "Unterminated string starting at"); free(b.p); return nullptr; }
        const char e = r->s[r->i + 1];
        r->i += 2;
        switch (e) {
        case '"': pw_buf_putc(&b, '"'); break;
        case '\\': pw_buf_putc(&b, '\\'); break;
        case '/': pw_buf_putc(&b, '/'); break;
        case 'b': pw_buf_putc(&b, '\b'); break;
        case 'f': pw_buf_putc(&b, '\f'); break;
        case 'n': pw_buf_putc(&b, '\n'); break;
        case 'r': pw_buf_putc(&b, '\r'); break;
        case 't': pw_buf_putc(&b, '\t'); break;
        case 'u': {
            uint32_t cp;
            if (hex4(r, r->i, &cp)) { fail(r, "Invalid \\uXXXX escape"); free(b.p); return nullptr; }
            r->i += 4;
            if (cp >= 0xD800 && cp <= 0xDBFF && r->i + 6 <= r->n && r->s[r->i] == '\\' && r->s[r->i + 1] == 'u') {
                uint32_t lo;
                if (hex4(r, r->i + 2, &lo) == 0 && lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    r->i += 6;
                }
            }
            put_utf8(&b, cp);
            break;
        }
        default:
            r->i -= 2;
            fail(r, "Invalid \\escape");
            free(b.p);
            return nullptr;
        }
    }
    return pw_buf_take(&b, len);
}

static pj *value(rd *r, int depth);

static pj *number(rd *r) {
    const size_t st = r->i;
    if (r->s[r->i] == '-') r->i++;
    if (r->i < r->n && r->s[r->i] == '0') r->i++;
    else if (r->i < r->n && r->s[r->i] >= '1' && r->s[r->i] <= '9') {
        while (r->i < r->n && r->s[r->i] >= '0' && r->s[r->i] <= '9') r->i++;
    } else {
        r->i = st;
        if (r->n - st >= 9 && memcmp(r->s + st, "-Infinity", 9) == 0) {
            r->i += 9;
            pj *v = mk(PJ_FLOAT);
            v->d = -INFINITY;
            return v;
        }
        fail(r, "Expecting value");
        return nullptr;
    }
    bool isf = false;
    if (r->i + 1 < r->n && r->s[r->i] == '.' && r->s[r->i + 1] >= '0' && r->s[r->i + 1] <= '9') {
        isf = true;
        r->i++;
        while (r->i < r->n && r->s[r->i] >= '0' && r->s[r->i] <= '9') r->i++;
    }
    if (r->i < r->n && (r->s[r->i] == 'e' || r->s[r->i] == 'E')) {
        size_t j = r->i + 1;
        if (j < r->n && (r->s[j] == '+' || r->s[j] == '-')) j++;
        if (j < r->n && r->s[j] >= '0' && r->s[j] <= '9') {
            while (j < r->n && r->s[j] >= '0' && r->s[j] <= '9') j++;
            r->i = j;
            isf = true;
        }
    }
    char *txt = pw_dupn(r->s + st, r->i - st);
    pj *v;
    if (isf) {
        v = mk(PJ_FLOAT);
        v->d = strtod(txt, nullptr);
    } else if (txt[0] == '-') {
        v = pj_int(strtoll(txt, nullptr, 10));
    } else {
        v = pj_uint(strtoull(txt, nullptr, 10));
    }
    free(txt);
    return v;
}

static pj *value(rd *r, int depth) {
    if (depth > 900) { fail(r, "maximum recursion depth exceeded"); return nullptr; }
    ws(r);
    if (r->i >= r->n) { fail(r, "Expecting value"); return nullptr; }
    const char c = r->s[r->i];
    if (c == '{') {
        pj *o = pj_obj();
        r->i++;
        ws(r);
        if (r->i < r->n && r->s[r->i] == '}') { r->i++; return o; }
        for (;;) {
            ws(r);
            if (r->i >= r->n || r->s[r->i] != '"') {
                fail(r, "Expecting property name enclosed in double quotes");
                pj_free(o);
                return nullptr;
            }
            size_t kl;
            char *k = read_string(r, &kl);
            if (k == nullptr) { pj_free(o); return nullptr; }
            ws(r);
            if (r->i >= r->n || r->s[r->i] != ':') { fail(r, "Expecting ':' delimiter"); free(k); pj_free(o); return nullptr; }
            r->i++;
            pj *v = value(r, depth + 1);
            if (v == nullptr) { free(k); pj_free(o); return nullptr; }
            pj_set(o, k, v);
            free(k);
            ws(r);
            if (r->i < r->n && r->s[r->i] == ',') { r->i++; continue; }
            if (r->i < r->n && r->s[r->i] == '}') { r->i++; return o; }
            fail(r, "Expecting ',' delimiter");
            pj_free(o);
            return nullptr;
        }
    }
    if (c == '[') {
        pj *a = pj_arr();
        r->i++;
        ws(r);
        if (r->i < r->n && r->s[r->i] == ']') { r->i++; return a; }
        for (;;) {
            pj *v = value(r, depth + 1);
            if (v == nullptr) { pj_free(a); return nullptr; }
            pj_push(a, v);
            ws(r);
            if (r->i < r->n && r->s[r->i] == ',') { r->i++; continue; }
            if (r->i < r->n && r->s[r->i] == ']') { r->i++; return a; }
            fail(r, "Expecting ',' delimiter");
            pj_free(a);
            return nullptr;
        }
    }
    if (c == '"') {
        size_t l;
        char *s = read_string(r, &l);
        if (s == nullptr) return nullptr;
        pj *v = mk(PJ_STR);
        v->s = s;
        v->slen = l;
        return v;
    }
    if (r->n - r->i >= 4 && memcmp(r->s + r->i, "null", 4) == 0) { r->i += 4; return pj_null(); }
    if (r->n - r->i >= 4 && memcmp(r->s + r->i, "true", 4) == 0) { r->i += 4; return pj_bool(true); }
    if (r->n - r->i >= 5 && memcmp(r->s + r->i, "false", 5) == 0) { r->i += 5; return pj_bool(false); }
    if (r->n - r->i >= 3 && memcmp(r->s + r->i, "NaN", 3) == 0) {
        r->i += 3;
        pj *v = mk(PJ_FLOAT);
        v->d = NAN;
        return v;
    }
    if (r->n - r->i >= 8 && memcmp(r->s + r->i, "Infinity", 8) == 0) {
        r->i += 8;
        pj *v = mk(PJ_FLOAT);
        v->d = INFINITY;
        return v;
    }
    if (c == '-' || (c >= '0' && c <= '9')) return number(r);
    fail(r, "Expecting value");
    return nullptr;
}

pj *pj_parse(const char *s, size_t len, char *err, size_t errcap) {
    rd r = { s, len, 0, err, errcap, false };
    pj *v = value(&r, 0);
    if (v == nullptr) return nullptr;
    ws(&r);
    if (r.i != r.n) {
        fail(&r, "Extra data");
        pj_free(v);
        return nullptr;
    }
    return v;
}
