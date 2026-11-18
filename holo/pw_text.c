/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Text, path and file helpers. C23 + POSIX. */
#define _POSIX_C_SOURCE 200809L
#include "pw_text.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

void pw_buf_put(pw_buf *b, const void *d, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 64;
        while (c < b->n + n + 1) c *= 2;
        char *p = realloc(b->p, c);
        if (p == nullptr) abort();
        b->p = p;
        b->cap = c;
    }
    if (n) memcpy(b->p + b->n, d, n);
    b->n += n;
    b->p[b->n] = 0;
}

void pw_buf_puts(pw_buf *b, const char *s) { pw_buf_put(b, s, strlen(s)); }

void pw_buf_putc(pw_buf *b, int c) {
    const char ch = (char)c;
    pw_buf_put(b, &ch, 1);
}

void pw_buf_printf(pw_buf *b, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    const int n = vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);
    if (n < 0) abort();
    pw_buf_put(b, "", 0);
    if (b->n + (size_t)n + 1 > b->cap) {
        size_t c = b->cap;
        while (c < b->n + (size_t)n + 1) c *= 2;
        char *p = realloc(b->p, c);
        if (p == nullptr) abort();
        b->p = p;
        b->cap = c;
    }
    vsnprintf(b->p + b->n, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    b->n += (size_t)n;
}

char *pw_buf_take(pw_buf *b, size_t *len) {
    pw_buf_put(b, "", 0);
    char *p = b->p;
    if (len) *len = b->n;
    b->p = nullptr;
    b->n = b->cap = 0;
    return p;
}

void pw_strv_push(pw_strv *sv, char *s) {
    if (sv->n == sv->cap) {
        sv->cap = sv->cap ? sv->cap * 2 : 8;
        sv->v = realloc(sv->v, sizeof *sv->v * sv->cap);
        if (sv->v == nullptr) abort();
    }
    sv->v[sv->n++] = s;
}

void pw_strv_free(pw_strv *sv) {
    for (size_t i = 0; i < sv->n; i++) free(sv->v[i]);
    free(sv->v);
    sv->v = nullptr;
    sv->n = sv->cap = 0;
}

bool pw_strv_has(const pw_strv *sv, const char *s) {
    for (size_t i = 0; i < sv->n; i++) {
        if (strcmp(sv->v[i], s) == 0) return true;
    }
    return false;
}

void pw_die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

char *pw_fmt(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    const int n = vsnprintf(nullptr, 0, fmt, ap);
    va_end(ap);
    if (n < 0) abort();
    char *o = malloc((size_t)n + 1);
    if (o == nullptr) abort();
    vsnprintf(o, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return o;
}

char *pw_dupn(const char *s, size_t n) {
    char *o = malloc(n + 1);
    if (o == nullptr) abort();
    if (n) memcpy(o, s, n);
    o[n] = 0;
    return o;
}

char *pw_dup(const char *s) { return pw_dupn(s, strlen(s)); }

bool pw_isspace(unsigned char c) { return c == ' ' || (c >= 9 && c <= 13) || (c >= 0x1c && c <= 0x1f); }

char *pw_strip(const char *s, size_t n) {
    size_t a = 0, b = n;
    while (a < b && pw_isspace((unsigned char)s[a])) a++;
    while (b > a && pw_isspace((unsigned char)s[b - 1])) b--;
    return pw_dupn(s + a, b - a);
}

pw_strv pw_split_ws(const char *s, size_t n, int maxsplit) {
    pw_strv sv = {0};
    size_t i = 0;
    int splits = 0;
    while (i < n) {
        while (i < n && pw_isspace((unsigned char)s[i])) i++;
        if (i >= n) break;
        if (maxsplit >= 0 && splits == maxsplit) {
            size_t e = n;
            while (e > i && pw_isspace((unsigned char)s[e - 1])) e--;
            pw_strv_push(&sv, pw_dupn(s + i, e - i));
            break;
        }
        const size_t st = i;
        while (i < n && !pw_isspace((unsigned char)s[i])) i++;
        pw_strv_push(&sv, pw_dupn(s + st, i - st));
        splits++;
    }
    return sv;
}

char *pw_wsjoin(const char *s, size_t n) {
    pw_strv sv = pw_split_ws(s, n, -1);
    pw_buf b = {0};
    pw_buf_put(&b, "", 0);
    for (size_t i = 0; i < sv.n; i++) {
        if (i) pw_buf_putc(&b, ' ');
        pw_buf_puts(&b, sv.v[i]);
    }
    pw_strv_free(&sv);
    return pw_buf_take(&b, nullptr);
}

pw_strv pw_split_ch(const char *s, size_t n, char sep) {
    pw_strv sv = {0};
    size_t st = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == sep) {
            pw_strv_push(&sv, pw_dupn(s + st, i - st));
            st = i + 1;
        }
    }
    return sv;
}

pw_strv pw_splitlines(const char *s, size_t n) {
    pw_strv sv = {0};
    size_t st = 0, i = 0;
    while (i < n) {
        const unsigned char c = (unsigned char)s[i];
        size_t brk = 0;
        if (c == '\r' && i + 1 < n && s[i + 1] == '\n') brk = 2;
        else if (c == '\n' || c == '\r' || c == '\v' || c == '\f' || c == 0x1c || c == 0x1d || c == 0x1e) brk = 1;
        else if (c == 0xC2 && i + 1 < n && (unsigned char)s[i + 1] == 0x85) brk = 2;
        else if (c == 0xE2 && i + 2 < n && (unsigned char)s[i + 1] == 0x80 &&
                 ((unsigned char)s[i + 2] == 0xA8 || (unsigned char)s[i + 2] == 0xA9)) brk = 3;
        if (brk) {
            pw_strv_push(&sv, pw_dupn(s + st, i - st));
            i += brk;
            st = i;
        } else {
            i++;
        }
    }
    if (st < n) pw_strv_push(&sv, pw_dupn(s + st, n - st));
    return sv;
}

char *pw_lower(const char *s) {
    char *o = pw_dup(s);
    for (char *p = o; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') *p = (char)(*p + 32);
    }
    return o;
}

char *pw_upper(const char *s) {
    char *o = pw_dup(s);
    for (char *p = o; *p; p++) {
        if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 32);
    }
    return o;
}

bool pw_startswith(const char *s, const char *prefix) { return strncmp(s, prefix, strlen(prefix)) == 0; }
bool pw_contains(const char *s, const char *needle) { return strstr(s, needle) != nullptr; }

size_t pw_cp_index(const char *s, size_t off) {
    size_t n = 0;
    for (size_t i = 0; i < off; i++) {
        if (((unsigned char)s[i] & 0xC0) != 0x80) n++;
    }
    return n;
}

uint8_t *pw_slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == nullptr) return nullptr;
    pw_buf b = {0};
    pw_buf_put(&b, "", 0);
    char tmp[65536];
    size_t r;
    while ((r = fread(tmp, 1, sizeof tmp, f)) > 0) pw_buf_put(&b, tmp, r);
    const bool err = ferror(f);
    fclose(f);
    if (err) {
        free(b.p);
        errno = EIO;
        return nullptr;
    }
    return (uint8_t *)pw_buf_take(&b, len);
}

/* Length of the valid UTF-8 sequence at d[i], or 0 with *bad set to the
 * number of bytes forming the maximal invalid prefix. */
static size_t utf8_seq(const uint8_t *d, size_t n, size_t i, size_t *bad) {
    const uint8_t c = d[i];
    if (c < 0x80) return 1;
    size_t need;
    uint8_t lo = 0x80, hi = 0xBF;
    if (c >= 0xC2 && c <= 0xDF) need = 1;
    else if (c == 0xE0) { need = 2; lo = 0xA0; }
    else if (c >= 0xE1 && c <= 0xEC) need = 2;
    else if (c == 0xED) { need = 2; hi = 0x9F; }
    else if (c >= 0xEE && c <= 0xEF) need = 2;
    else if (c == 0xF0) { need = 3; lo = 0x90; }
    else if (c >= 0xF1 && c <= 0xF3) need = 3;
    else if (c == 0xF4) { need = 3; hi = 0x8F; }
    else { *bad = 1; return 0; }
    for (size_t k = 1; k <= need; k++) {
        const uint8_t l = k == 1 ? lo : 0x80, h = k == 1 ? hi : 0xBF;
        if (i + k >= n || d[i + k] < l || d[i + k] > h) { *bad = k; return 0; }
    }
    return need + 1;
}

bool pw_utf8_valid(const uint8_t *d, size_t n) {
    size_t i = 0, bad;
    while (i < n) {
        const size_t l = utf8_seq(d, n, i, &bad);
        if (l == 0) return false;
        i += l;
    }
    return true;
}

char *pw_decode_text(const uint8_t *d, size_t n, size_t *out_len) {
    pw_buf b = {0};
    pw_buf_put(&b, "", 0);
    size_t i = 0, bad;
    while (i < n) {
        if (d[i] == '\r') {
            pw_buf_putc(&b, '\n');
            i += (i + 1 < n && d[i + 1] == '\n') ? 2 : 1;
            continue;
        }
        const size_t l = utf8_seq(d, n, i, &bad);
        if (l == 0) {
            pw_buf_put(&b, "\xEF\xBF\xBD", 3);
            i += bad;
        } else {
            pw_buf_put(&b, d + i, l);
            i += l;
        }
    }
    return pw_buf_take(&b, out_len);
}

char *pw_read_text(const char *path, size_t *len) {
    size_t n;
    uint8_t *d = pw_slurp(path, &n);
    if (d == nullptr) return nullptr;
    char *t = pw_decode_text(d, n, len);
    free(d);
    return t;
}

char *pw_path_norm(const char *p) {
    pw_buf b = {0};
    pw_buf_put(&b, "", 0);
    size_t i = 0;
    if (p[0] == '/') {
        if (p[1] == '/' && p[2] != '/') { pw_buf_puts(&b, "//"); i = 2; }
        else pw_buf_putc(&b, '/');
    }
    const size_t root = b.n;
    while (p[i]) {
        while (p[i] == '/') i++;
        const size_t st = i;
        while (p[i] && p[i] != '/') i++;
        const size_t l = i - st;
        if (l == 0 || (l == 1 && p[st] == '.')) continue;
        if (b.n > root) pw_buf_putc(&b, '/');
        pw_buf_put(&b, p + st, l);
    }
    if (b.n == 0) pw_buf_putc(&b, '.');
    return pw_buf_take(&b, nullptr);
}

char *pw_path_name(const char *p) {
    char *n = pw_path_norm(p);
    const char *s = strrchr(n, '/');
    char *o = pw_dup(s ? s + 1 : n);
    if (strcmp(o, ".") == 0) o[0] = 0;
    free(n);
    return o;
}

char *pw_path_suffix(const char *p) {
    char *name = pw_path_name(p);
    const char *dot = strrchr(name, '.');
    const size_t i = dot ? (size_t)(dot - name) : 0;
    char *o = (dot && i > 0 && i < strlen(name) - 1) ? pw_dup(dot) : pw_dup("");
    free(name);
    return o;
}

char *pw_path_stem(const char *p) {
    char *name = pw_path_name(p);
    char *dot = strrchr(name, '.');
    const size_t i = dot ? (size_t)(dot - name) : 0;
    if (dot && i > 0 && i < strlen(name) - 1) *dot = 0;
    return name;
}

char *pw_path_parent(const char *p) {
    char *n = pw_path_norm(p);
    char *s = strrchr(n, '/');
    if (s == nullptr) { free(n); return pw_dup("."); }
    if (s == n) { n[1] = 0; return n; }
    if (s == n + 1 && n[0] == '/') { n[2] = 0; return n; }
    *s = 0;
    return n;
}

char *pw_path_join(const char *a, const char *b) {
    if (b[0] == '/') return pw_path_norm(b);
    char *j = pw_fmt("%s/%s", a, b);
    char *n = pw_path_norm(j);
    free(j);
    return n;
}

bool pw_path_exists(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

bool pw_path_isdir(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

int pw_mkdirs(const char *p) {
    char *n = pw_path_norm(p);
    const size_t len = strlen(n);
    for (size_t i = 1; i <= len; i++) {
        if (n[i] == '/' || n[i] == 0) {
            const char save = n[i];
            n[i] = 0;
            if (mkdir(n, 0777) != 0 && errno != EEXIST) { free(n); return -1; }
            n[i] = save;
        }
    }
    const bool ok = pw_path_isdir(n);
    free(n);
    return ok ? 0 : -1;
}

/* pathlib sorts by path components. */
static int cmp_parts(const void *a, const void *b) {
    const char *x = *(char *const *)a, *y = *(char *const *)b;
    for (;;) {
        const size_t lx = strcspn(x, "/"), ly = strcspn(y, "/");
        const size_t m = lx < ly ? lx : ly;
        const int c = memcmp(x, y, m);
        if (c) return c;
        if (lx != ly) return lx < ly ? -1 : 1;
        if (!x[lx] || !y[ly]) return (x[lx] ? 1 : 0) - (y[ly] ? 1 : 0);
        x += lx + 1;
        y += ly + 1;
    }
}

static void walk(const char *dir, const char *suffix, pw_strv *out) {
    DIR *d = opendir(dir);
    if (d == nullptr) return;
    struct dirent *e;
    const size_t sl = strlen(suffix);
    while ((e = readdir(d)) != nullptr) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char *full = pw_path_join(dir, e->d_name);
        struct stat ls, st;
        if (lstat(full, &ls) != 0) { free(full); continue; }
        if (S_ISDIR(ls.st_mode)) {
            walk(full, suffix, out);
            free(full);
            continue;
        }
        const size_t nl = strlen(e->d_name);
        const bool dir_link = S_ISLNK(ls.st_mode) && stat(full, &st) == 0 && S_ISDIR(st.st_mode);
        if (!dir_link && nl >= sl && strcmp(e->d_name + nl - sl, suffix) == 0) pw_strv_push(out, full);
        else free(full);
    }
    closedir(d);
}

pw_strv pw_rglob_suffix(const char *dir, const char *suffix) {
    pw_strv out = {0};
    char *n = pw_path_norm(dir);
    walk(n, suffix, &out);
    free(n);
    if (out.n > 1) qsort(out.v, out.n, sizeof *out.v, cmp_parts);
    return out;
}

int pw_spit(const char *path, const void *d, size_t n) {
    FILE *f = fopen(path, "wb");
    if (f == nullptr) return -1;
    const bool ok = fwrite(d, 1, n, f) == n;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}
