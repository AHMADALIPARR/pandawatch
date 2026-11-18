/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* JSON values with insertion-ordered objects. The writer produces the same
 * bytes as Python's json.dumps with ensure_ascii=True: compact with
 * separators (",", ":"), or indent=N with (",", ": "), optionally with
 * sort_keys. The reader follows json.loads (duplicate keys: last value wins,
 * first position kept; NaN / Infinity accepted). C23. */
#ifndef PW_JSON_H
#define PW_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { PJ_NULL, PJ_BOOL, PJ_INT, PJ_UINT, PJ_FLOAT, PJ_STR, PJ_ARR, PJ_OBJ } pj_type;

typedef struct pj pj;
struct pj {
    pj_type t;
    bool b;
    int64_t i;
    uint64_t u;
    double d;
    char *s;        /* PJ_STR: UTF-8, may hold NUL bytes */
    size_t slen;
    size_t n, cap;  /* PJ_ARR / PJ_OBJ */
    pj **v;
    char **k;       /* PJ_OBJ keys */
};

[[nodiscard]] pj *pj_null(void);
[[nodiscard]] pj *pj_bool(bool b);
[[nodiscard]] pj *pj_int(int64_t i);
[[nodiscard]] pj *pj_uint(uint64_t u);
[[nodiscard]] pj *pj_str(const char *s);  /* nullptr gives JSON null */
[[nodiscard]] pj *pj_strn(const char *s, size_t n);
[[nodiscard]] pj *pj_strown(char *s);   /* takes a malloc'd string */
[[nodiscard]] pj *pj_arr(void);
[[nodiscard]] pj *pj_obj(void);
[[nodiscard]] pj *pj_copy(const pj *v);
void pj_free(pj *v);

void pj_push(pj *arr, pj *v);
void pj_set(pj *obj, const char *key, pj *v);   /* replaces in place if present */
[[nodiscard]] pj *pj_get(const pj *obj, const char *key);
[[nodiscard]] int64_t pj_as_int(const pj *v);    /* ints, bools, floats truncated */
[[nodiscard]] const char *pj_as_str(const pj *v); /* "" when not a string */
[[nodiscard]] bool pj_truthy(const pj *v);

/* indent < 0: compact (",", ":"); indent >= 0: Python indent=N. */
[[nodiscard]] char *pj_dump(const pj *v, int indent, bool sort_keys, size_t *len);
/* Python str() / repr() style text of a value (used for dict / list prints). */
[[nodiscard]] char *pj_pyrepr(const pj *v);

/* Returns nullptr and writes a json.JSONDecodeError style message on error. */
[[nodiscard]] pj *pj_parse(const char *s, size_t len, char *err, size_t errcap);

#endif /* PW_JSON_H */
