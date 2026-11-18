/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Backtracking regular expressions with the semantics of the pattern subset
 * the holo tools use: literals, `.`, classes `[...]` / `[^...]`, `\d \w \s`
 * and their negations, `\b \B`, `^ $`, capturing and `(?:...)` groups, `|`,
 * greedy and lazy `* + ? {m} {m,} {m,n}`. Flags: IGNORECASE (ASCII),
 * MULTILINE, DOTALL. Leftmost match, first alternative wins. Bytes >= 0x80
 * count as word characters. C23. */
#ifndef PW_RE_H
#define PW_RE_H

#include <stdbool.h>
#include <stddef.h>

enum { PW_RE_I = 1, PW_RE_M = 2, PW_RE_S = 4 };
enum { PW_RE_MAXCAP = 16 };

typedef struct pw_re pw_re;

typedef struct {
    long so[PW_RE_MAXCAP];  /* -1 when the group did not take part */
    long eo[PW_RE_MAXCAP];
} pw_rm;

/* Aborts with a message on a malformed pattern (patterns are constants). */
[[nodiscard]] pw_re *pw_re_compile(const char *pattern, int flags);
void pw_re_free(pw_re *re);

/* Anchored at pos (re.match when pos is 0). Group 0 is the whole match. */
bool pw_re_match_at(const pw_re *re, const char *s, size_t len, size_t pos, pw_rm *m);
/* First match starting at or after pos (re.search / one finditer step). */
bool pw_re_search(const pw_re *re, const char *s, size_t len, size_t pos, pw_rm *m);
/* re.sub(pattern, "", s): returns a malloc'd NUL-terminated copy. */
[[nodiscard]] char *pw_re_sub_empty(const pw_re *re, const char *s, size_t len, size_t *out_len);
/* re.sub(pattern, repl, s) with a literal replacement. */
[[nodiscard]] char *pw_re_sub_lit(const pw_re *re, const char *s, size_t len, const char *repl,
                                  size_t *out_len);

/* Group text as a malloc'd string, or nullptr when the group is unset. */
[[nodiscard]] char *pw_rm_dup(const pw_rm *m, int g, const char *s);
bool pw_rm_set(const pw_rm *m, int g);

/* finditer: `for (size_t p = 0; pw_re_next(re, s, len, &p, &m);)`. */
bool pw_re_next(const pw_re *re, const char *s, size_t len, size_t *pos, pw_rm *m);

#endif /* PW_RE_H */
