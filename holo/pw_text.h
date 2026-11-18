/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Text, path and file helpers shared by rblob, bsm and holo-reverse:
 * growable buffers, whitespace split/strip/join, UTF-8 decoding with U+FFFD
 * replacement plus universal newlines (how the original tools read source
 * text), path normalisation and name / stem / suffix, mkdir -p, and a sorted
 * recursive file search. C23 + POSIX. */
#ifndef PW_TEXT_H
#define PW_TEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *p;
    size_t n, cap;
} pw_buf;

void pw_buf_put(pw_buf *b, const void *d, size_t n);
void pw_buf_puts(pw_buf *b, const char *s);
void pw_buf_putc(pw_buf *b, int c);
void pw_buf_printf(pw_buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* NUL-terminates and hands the storage over. */
[[nodiscard]] char *pw_buf_take(pw_buf *b, size_t *len);

typedef struct {
    char **v;
    size_t n, cap;
} pw_strv;

void pw_strv_push(pw_strv *sv, char *s);   /* takes ownership */
void pw_strv_free(pw_strv *sv);
bool pw_strv_has(const pw_strv *sv, const char *s);

[[noreturn]] void pw_die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
[[nodiscard]] char *pw_fmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
[[nodiscard]] char *pw_dupn(const char *s, size_t n);
[[nodiscard]] char *pw_dup(const char *s);

bool pw_isspace(unsigned char c);
/* str.strip(): malloc'd. */
[[nodiscard]] char *pw_strip(const char *s, size_t n);
/* " ".join(s.split()) */
[[nodiscard]] char *pw_wsjoin(const char *s, size_t n);
/* s.split(None, maxsplit); maxsplit < 0 for no limit. */
[[nodiscard]] pw_strv pw_split_ws(const char *s, size_t n, int maxsplit);
/* s.split(sep) for a one-character separator. */
[[nodiscard]] pw_strv pw_split_ch(const char *s, size_t n, char sep);
/* s.splitlines() */
[[nodiscard]] pw_strv pw_splitlines(const char *s, size_t n);
[[nodiscard]] char *pw_lower(const char *s);
[[nodiscard]] char *pw_upper(const char *s);
bool pw_startswith(const char *s, const char *prefix);
bool pw_contains(const char *s, const char *needle);
/* Index in code points of byte offset off (for Python str positions). */
size_t pw_cp_index(const char *s, size_t off);

/* Bytes of a file, or nullptr with errno set. */
[[nodiscard]] uint8_t *pw_slurp(const char *path, size_t *len);
/* UTF-8 with errors="replace" and universal newlines, NUL-terminated. */
[[nodiscard]] char *pw_decode_text(const uint8_t *d, size_t n, size_t *out_len);
[[nodiscard]] char *pw_read_text(const char *path, size_t *len);
/* Strict UTF-8 check (bytes.decode("utf-8") succeeds). */
bool pw_utf8_valid(const uint8_t *d, size_t n);

/* str(pathlib.Path(p)). */
[[nodiscard]] char *pw_path_norm(const char *p);
[[nodiscard]] char *pw_path_name(const char *p);
[[nodiscard]] char *pw_path_suffix(const char *p);
[[nodiscard]] char *pw_path_stem(const char *p);
[[nodiscard]] char *pw_path_parent(const char *p);
[[nodiscard]] char *pw_path_join(const char *a, const char *b);
bool pw_path_exists(const char *p);
bool pw_path_isdir(const char *p);
/* Path.mkdir(parents=True, exist_ok=True); 0 on success. */
int pw_mkdirs(const char *p);
/* sorted(Path(dir).rglob("*" + suffix)), regular files and file symlinks. */
[[nodiscard]] pw_strv pw_rglob_suffix(const char *dir, const char *suffix);
/* Writes a whole file; 0 on success. */
int pw_spit(const char *path, const void *d, size_t n);

#endif /* PW_TEXT_H */
