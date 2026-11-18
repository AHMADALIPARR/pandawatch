/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* SQLite file-format reader and DDL model. C23. */
#include "pw_sqlite.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "pw_re.h"
#include "pw_text.h"

/* ------------------------------------------------------------------ */
/* Tokenizer (SQLite lexical rules)                                    */
/* ------------------------------------------------------------------ */

typedef enum { T_ID, T_QID, T_STR, T_NUM, T_BLOB, T_VAR, T_OP, T_SEMI, T_EOF } ttype;

typedef struct {
    ttype t;
    size_t s, n;   /* byte span in the source */
} tok;

typedef struct {
    tok *v;
    size_t n, cap;
} tokv;

static bool id_start(unsigned char c) { return c >= 0x80 || c == '_' || ((c | 32) >= 'a' && (c | 32) <= 'z'); }
static bool id_char(unsigned char c) { return id_start(c) || (c >= '0' && c <= '9') || c == '$'; }
static bool is_dig(unsigned char c) { return c >= '0' && c <= '9'; }

static void push_tok(tokv *tv, ttype t, size_t s, size_t n) {
    if (tv->n == tv->cap) {
        tv->cap = tv->cap ? tv->cap * 2 : 64;
        tv->v = realloc(tv->v, sizeof *tv->v * tv->cap);
        if (tv->v == nullptr) abort();
    }
    tv->v[tv->n++] = (tok){ t, s, n };
}

/* Returns false on an unrecognised character or unterminated quote. */
static bool tokenize(const char *src, size_t len, tokv *tv) {
    size_t i = 0;
    while (i < len) {
        const unsigned char c = (unsigned char)src[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r') { i++; continue; }
        if (c == '-' && i + 1 < len && src[i + 1] == '-') {
            while (i < len && src[i] != '\n') i++;
            continue;
        }
        if (c == '/' && i + 1 < len && src[i + 1] == '*') {
            i += 2;
            while (i < len && !(src[i] == '*' && i + 1 < len && src[i + 1] == '/')) i++;
            i = i < len ? i + 2 : len;
            continue;
        }
        const size_t st = i;
        if (c == ';') { push_tok(tv, T_SEMI, i, 1); i++; continue; }
        if ((c == 'x' || c == 'X') && i + 1 < len && src[i + 1] == '\'') {
            i += 2;
            while (i < len && src[i] != '\'') i++;
            if (i >= len) return false;
            i++;
            push_tok(tv, T_BLOB, st, i - st);
            continue;
        }
        if (id_start(c)) {
            while (i < len && id_char((unsigned char)src[i])) i++;
            push_tok(tv, T_ID, st, i - st);
            continue;
        }
        if (c == '\'' || c == '"' || c == '`') {
            i++;
            for (;;) {
                if (i >= len) return false;
                if ((unsigned char)src[i] == c) {
                    if (i + 1 < len && (unsigned char)src[i + 1] == c) { i += 2; continue; }
                    i++;
                    break;
                }
                i++;
            }
            push_tok(tv, c == '\'' ? T_STR : T_QID, st, i - st);
            continue;
        }
        if (c == '[') {
            while (i < len && src[i] != ']') i++;
            if (i >= len) return false;
            i++;
            push_tok(tv, T_QID, st, i - st);
            continue;
        }
        if (is_dig(c) || (c == '.' && i + 1 < len && is_dig((unsigned char)src[i + 1]))) {
            if (c == '0' && i + 1 < len && (src[i + 1] | 32) == 'x') {
                i += 2;
                while (i < len && (is_dig((unsigned char)src[i]) || ((src[i] | 32) >= 'a' && (src[i] | 32) <= 'f'))) i++;
            } else {
                while (i < len && (is_dig((unsigned char)src[i]) || src[i] == '_')) i++;
                if (i < len && src[i] == '.') { i++; while (i < len && is_dig((unsigned char)src[i])) i++; }
                if (i < len && (src[i] | 32) == 'e') {
                    size_t j = i + 1;
                    if (j < len && (src[j] == '+' || src[j] == '-')) j++;
                    if (j < len && is_dig((unsigned char)src[j])) {
                        while (j < len && is_dig((unsigned char)src[j])) j++;
                        i = j;
                    }
                }
            }
            if (i < len && id_char((unsigned char)src[i])) return false;
            push_tok(tv, T_NUM, st, i - st);
            continue;
        }
        if (c == '?' || c == ':' || c == '@' || c == '$' || c == '#') {
            i++;
            while (i < len && id_char((unsigned char)src[i])) i++;
            push_tok(tv, T_VAR, st, i - st);
            continue;
        }
        static const char *const ops2[] = { "||", "<=", ">=", "==", "!=", "<>", "<<", ">>", "->" };
        bool two = false;
        for (size_t k = 0; k < sizeof ops2 / sizeof ops2[0]; k++) {
            if (i + 1 < len && src[i] == ops2[k][0] && src[i + 1] == ops2[k][1]) { two = true; break; }
        }
        if (two) {
            const size_t n = (src[i] == '-' && i + 2 < len && src[i + 2] == '>') ? 3 : 2;
            push_tok(tv, T_OP, st, n);
            i += n;
            continue;
        }
        if (strchr("(),.+-*/%<>=&|~!", c) && c) { push_tok(tv, T_OP, i, 1); i++; continue; }
        return false;
    }
    push_tok(tv, T_EOF, len, 0);
    return true;
}

/* sqlite3Dequote: strips one level of '', "", ``, [] quoting. */
static char *dequote(const char *s, size_t n) {
    if (n < 2) return pw_dupn(s, n);
    char q = s[0];
    if (q == '[') q = ']';
    else if (q != '\'' && q != '"' && q != '`') return pw_dupn(s, n);
    char *o = malloc(n);
    if (o == nullptr) abort();
    size_t k = 0;
    for (size_t i = 1; i < n; i++) {
        if (s[i] == q) {
            if (q != ']' && i + 1 < n && s[i + 1] == q) { o[k++] = q; i++; continue; }
            break;
        }
        o[k++] = s[i];
    }
    o[k] = 0;
    return o;
}

/* ------------------------------------------------------------------ */
/* Schema model                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    char *name, *type;
    bool notnull, pk, hidden;
    char aff;   /* 'I' integer, 'T' text, 'B' blob, 'R' real, 'N' numeric */
} sq_col;

typedef struct {
    char *from, *to_table, *to_col;
    int id, seq;
} sq_fk;

typedef struct {
    char *name;
    pw_strv cols;   /* lower-cased key columns of a constraint index */
    bool constraint;
} sq_idx;

typedef struct {
    pw_strv vals;   /* normalised literal keys already present */
    int col;        /* column index */
    bool is_pk;
} sq_uniq;

typedef struct {
    char *name, *sql;
    sq_col *cols;
    size_t ncols;
    sq_fk *fks;     /* PRAGMA foreign_key_list order */
    size_t nfks;
    sq_idx *idx;    /* PRAGMA index_list order (newest first) */
    size_t nidx;
    long rows;
    long long next_rowid;
    int ipk;        /* rowid alias column, -1 if none */
    bool temp, without_rowid, rows_known;
    size_t add_col_off;  /* byte offset in sql after the last column def */
    sq_uniq *uq;
    size_t nuq;
    unsigned rootpage;
} sq_table;

typedef struct {
    sq_table *t;
    size_t n;
    char err[256];
    const char *file;
} sq_db;

static sq_table *find_table(sq_db *db, const char *name) {
    for (size_t i = 0; i < db->n; i++) {
        if (strcasecmp(db->t[i].name, name) == 0) return &db->t[i];
    }
    return nullptr;
}

static char col_affinity(const char *type) {
    char *u = pw_upper(type);
    char a = 'N';
    if (strstr(u, "INT")) a = 'I';
    else if (strstr(u, "CHAR") || strstr(u, "CLOB") || strstr(u, "TEXT")) a = 'T';
    else if (strstr(u, "BLOB") || !u[0]) a = 'B';
    else if (strstr(u, "REAL") || strstr(u, "FLOA") || strstr(u, "DOUB")) a = 'R';
    free(u);
    return a;
}

/* ------------------------------------------------------------------ */
/* Parser helpers                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *src;
    const tok *v;
    size_t n, i;
    sq_db *db;
    bool failed;
} ps;

static const tok *cur(const ps *p) { return &p->v[p->i < p->n ? p->i : p->n - 1]; }
static bool kw_at(const ps *p, size_t i, const char *kw) {
    if (i >= p->n) return false;
    const tok *t = &p->v[i];
    return t->t == T_ID && strlen(kw) == t->n && strncasecmp(p->src + t->s, kw, t->n) == 0;
}
static bool kw(const ps *p, const char *k) { return kw_at(p, p->i, k); }
static bool op_at(const ps *p, size_t i, const char *o) {
    if (i >= p->n) return false;
    const tok *t = &p->v[i];
    return t->t == T_OP && strlen(o) == t->n && strncmp(p->src + t->s, o, t->n) == 0;
}
static bool op(const ps *p, const char *o) { return op_at(p, p->i, o); }
static bool accept_kw(ps *p, const char *k) { if (kw(p, k)) { p->i++; return true; } return false; }
static bool accept_op(ps *p, const char *o) { if (op(p, o)) { p->i++; return true; } return false; }

static void perr(ps *p, const char *msg) {
    if (!p->failed) {
        p->failed = true;
        snprintf(p->db->err, sizeof p->db->err, "%s", msg);
    }
}

static bool expect_kw(ps *p, const char *k) {
    if (accept_kw(p, k)) return true;
    perr(p, "syntax error");
    return false;
}
static bool expect_op(ps *p, const char *o) {
    if (accept_op(p, o)) return true;
    perr(p, "syntax error");
    return false;
}

/* Words that cannot be a bare identifier (column / table names). */
static bool reserved(const ps *p, size_t i) {
    static const char *const r[] = {
        "ADD", "ALL", "ALTER", "AND", "AS", "AUTOINCREMENT", "BETWEEN", "CASE", "CHECK", "COLLATE",
        "COMMIT", "CONSTRAINT", "CREATE", "DEFAULT", "DEFERRABLE", "DELETE", "DISTINCT", "DROP",
        "ELSE", "ESCAPE", "EXCEPT", "EXISTS", "FOREIGN", "FROM", "GROUP", "HAVING", "IN", "INDEX",
        "INSERT", "INTERSECT", "INTO", "IS", "ISNULL", "JOIN", "LIMIT", "NOT", "NOTNULL", "NULL",
        "ON", "OR", "ORDER", "PRIMARY", "REFERENCES", "SELECT", "SET", "TABLE", "THEN", "TO",
        "TRANSACTION", "UNION", "UNIQUE", "UPDATE", "USING", "VALUES", "WHEN", "WHERE",
    };
    for (size_t k = 0; k < sizeof r / sizeof r[0]; k++) {
        if (kw_at(p, i, r[k])) return true;
    }
    return false;
}

/* nm ::= id | STRING | JOIN_KW */
static bool name_tok(ps *p, char **out, const tok **t) {
    const tok *c = cur(p);
    if ((c->t == T_ID && !reserved(p, p->i)) || c->t == T_QID || c->t == T_STR) {
        if (out) *out = dequote(p->src + c->s, c->n);
        if (t) *t = c;
        p->i++;
        return true;
    }
    perr(p, "syntax error");
    return false;
}

/* Skips a parenthesised group starting at '('. */
static bool skip_parens(ps *p) {
    if (!expect_op(p, "(")) return false;
    int depth = 1;
    while (depth > 0) {
        const tok *c = cur(p);
        if (c->t == T_EOF || c->t == T_SEMI) { perr(p, "incomplete input"); return false; }
        if (op(p, "(")) depth++;
        else if (op(p, ")")) depth--;
        p->i++;
    }
    return true;
}

/* Skips one expression up to a top-level ',' or ')' or ';'. */
static void skip_expr(ps *p) {
    int depth = 0;
    for (;;) {
        const tok *c = cur(p);
        if (c->t == T_EOF || c->t == T_SEMI) return;
        if (depth == 0 && (op(p, ",") || op(p, ")"))) return;
        if (op(p, "(")) depth++;
        else if (op(p, ")")) depth--;
        p->i++;
    }
}

static void conflict_clause(ps *p) {
    if (kw(p, "ON") && kw_at(p, p->i + 1, "CONFLICT")) {
        p->i += 2;
        if (accept_kw(p, "ROLLBACK") || accept_kw(p, "ABORT") || accept_kw(p, "FAIL") ||
            accept_kw(p, "IGNORE") || accept_kw(p, "REPLACE")) return;
        perr(p, "syntax error");
    }
}

/* ( indexed-column, ... ) -> lower-cased names; DESC flag of the first. */
static bool col_list(ps *p, pw_strv *out, bool *first_desc, bool allow_expr) {
    if (!expect_op(p, "(")) return false;
    bool first = true;
    for (;;) {
        char *nm = nullptr;
        const tok *c = cur(p);
        if (c->t == T_ID || c->t == T_QID || c->t == T_STR) {
            nm = dequote(p->src + c->s, c->n);
            p->i++;
        } else if (!allow_expr) {
            perr(p, "syntax error");
            return false;
        }
        if (nm == nullptr || !(op(p, ",") || op(p, ")") || kw(p, "COLLATE") || kw(p, "ASC") || kw(p, "DESC"))) {
            if (!allow_expr) { free(nm); perr(p, "expressions prohibited in PRIMARY KEY and UNIQUE constraints"); return false; }
            free(nm);
            nm = pw_dup("");
            skip_expr(p);
        }
        if (accept_kw(p, "COLLATE")) { if (!name_tok(p, nullptr, nullptr)) { free(nm); return false; } }
        bool desc = false;
        if (accept_kw(p, "DESC")) desc = true;
        else accept_kw(p, "ASC");
        if (first && first_desc) *first_desc = desc;
        first = false;
        char *l = pw_lower(nm);
        free(nm);
        pw_strv_push(out, l);
        if (accept_op(p, ",")) continue;
        return expect_op(p, ")");
    }
}

static int col_index(const sq_table *t, const char *lname) {
    for (size_t i = 0; i < t->ncols; i++) {
        if (strcasecmp(t->cols[i].name, lname) == 0) return (int)i;
    }
    return -1;
}

static void add_index(sq_table *t, char *name, pw_strv cols, bool constraint) {
    sq_idx *v = realloc(t->idx, sizeof *v * (t->nidx + 1));
    if (v == nullptr) abort();
    t->idx = v;
    memmove(t->idx + 1, t->idx, sizeof *t->idx * t->nidx);
    t->idx[0] = (sq_idx){ name, cols, constraint };
    t->nidx++;
}

/* sqlite3CreateIndex for a PRIMARY KEY / UNIQUE constraint. */
static void constraint_index(sq_table *t, pw_strv cols) {
    for (size_t i = 0; i < t->nidx; i++) {
        if (!t->idx[i].constraint || t->idx[i].cols.n != cols.n) continue;
        bool same = true;
        for (size_t k = 0; k < cols.n && same; k++) same = strcmp(t->idx[i].cols.v[k], cols.v[k]) == 0;
        if (same) { pw_strv_free(&cols); return; }
    }
    add_index(t, pw_fmt("sqlite_autoindex_%s_%zu", t->name, t->nidx + 1), cols, true);
}

static void add_uniq(sq_table *t, int col, bool is_pk) {
    sq_uniq *v = realloc(t->uq, sizeof *v * (t->nuq + 1));
    if (v == nullptr) abort();
    t->uq = v;
    t->uq[t->nuq++] = (sq_uniq){ { nullptr, 0, 0 }, col, is_pk };
}

typedef struct {
    pw_strv from, to;
    char *table;
} fk_pending;

static bool col_list_raw(ps *p, pw_strv *out);

/* REFERENCES tbl [(cols)] {ON DELETE|UPDATE action | MATCH name} [deferrable] */
static bool fk_clause(ps *p, fk_pending *fk) {
    if (!expect_kw(p, "REFERENCES")) return false;
    if (!name_tok(p, &fk->table, nullptr)) return false;
    if (op(p, "(") && !col_list_raw(p, &fk->to)) return false;
    for (;;) {
        if (kw(p, "ON") && (kw_at(p, p->i + 1, "DELETE") || kw_at(p, p->i + 1, "UPDATE"))) {
            p->i += 2;
            if (accept_kw(p, "SET")) { if (!accept_kw(p, "NULL") && !accept_kw(p, "DEFAULT")) { perr(p, "syntax error"); return false; } }
            else if (accept_kw(p, "CASCADE") || accept_kw(p, "RESTRICT")) {}
            else if (accept_kw(p, "NO")) { if (!expect_kw(p, "ACTION")) return false; }
            else { perr(p, "syntax error"); return false; }
            continue;
        }
        if (accept_kw(p, "MATCH")) { if (!name_tok(p, nullptr, nullptr)) return false; continue; }
        break;
    }
    const size_t save = p->i;
    accept_kw(p, "NOT");
    if (accept_kw(p, "DEFERRABLE")) {
        if (accept_kw(p, "INITIALLY")) {
            if (!accept_kw(p, "DEFERRED") && !accept_kw(p, "IMMEDIATE")) { perr(p, "syntax error"); return false; }
        }
    } else {
        p->i = save;
    }
    return true;
}

static void add_fk(sq_table *t, fk_pending *fk, sq_db *db, ps *p) {
    if (fk->to.n && fk->to.n != fk->from.n) {
        perr(p, "number of columns in foreign key does not match the number of columns in the referenced table");
        (void)db;
        return;
    }
    /* New foreign keys go to the front of the list; ids are assigned in
     * list order and each key's columns keep their order (seq). */
    const size_t add = fk->from.n;
    sq_fk *v = realloc(t->fks, sizeof *v * (t->nfks + add));
    if (v == nullptr) abort();
    t->fks = v;
    memmove(t->fks + add, t->fks, sizeof *t->fks * t->nfks);
    for (size_t k = 0; k < add; k++) {
        const int ci = col_index(t, fk->from.v[k]);
        t->fks[k] = (sq_fk){ pw_dup(ci >= 0 ? t->cols[ci].name : fk->from.v[k]), pw_dup(fk->table),
                             fk->to.n ? pw_dup(fk->to.v[k]) : nullptr, 0, (int)k };
    }
    t->nfks += add;
    int id = -1;
    for (size_t k = 0; k < t->nfks; k++) {
        if (t->fks[k].seq == 0) id++;
        t->fks[k].id = id;
    }
}

/* to-column names keep their spelling from the REFERENCES clause. */
static bool col_list_raw(ps *p, pw_strv *out) {
    if (!expect_op(p, "(")) return false;
    for (;;) {
        char *nm;
        if (!name_tok(p, &nm, nullptr)) return false;
        pw_strv_push(out, nm);
        if (accept_kw(p, "COLLATE")) { if (!name_tok(p, nullptr, nullptr)) return false; }
        if (!accept_kw(p, "ASC")) accept_kw(p, "DESC");
        if (accept_op(p, ",")) continue;
        return expect_op(p, ")");
    }
}

static void free_fkp(fk_pending *fk) {
    pw_strv_free(&fk->from);
    pw_strv_free(&fk->to);
    free(fk->table);
    *fk = (fk_pending){0};
}

static const char *const STD_TYPES[] = { "ANY", "BLOB", "INT", "INTEGER", "REAL", "TEXT" };

/* Column type text as PRAGMA table_info reports it. */
static char *column_type(const char *src, size_t s, size_t n) {
    /* "... GENERATED ALWAYS" swallowed into the type name is dropped. */
    if (n >= 16 && strncasecmp(src + s + n - 6, "always", 6) == 0) {
        n -= 6;
        while (n > 0 && pw_isspace((unsigned char)src[s + n - 1])) n--;
        if (n >= 9 && strncasecmp(src + s + n - 9, "generated", 9) == 0) {
            n -= 9;
            while (n > 0 && pw_isspace((unsigned char)src[s + n - 1])) n--;
        }
    }
    char *t = dequote(src + s, n);
    for (size_t k = 0; k < sizeof STD_TYPES / sizeof STD_TYPES[0]; k++) {
        if (strcasecmp(t, STD_TYPES[k]) == 0) { free(t); return pw_dup(STD_TYPES[k]); }
    }
    return t;
}

static bool is_col_cons_kw(const ps *p) {
    static const char *const k[] = { "CONSTRAINT", "PRIMARY", "NOT", "NULL", "UNIQUE", "CHECK", "DEFAULT",
                                     "COLLATE", "REFERENCES", "AS" };
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        if (kw(p, k[i])) return true;
    }
    return false;
}

static bool add_column(ps *p, sq_table *t) {
    char *name;
    if (!name_tok(p, &name, nullptr)) return false;
    if (col_index(t, name) >= 0) {
        char msg[200];
        snprintf(msg, sizeof msg, "duplicate column name: %s", name);
        free(name);
        perr(p, msg);
        return false;
    }
    size_t ts = 0, te = 0;
    bool has_type = false;
    while (cur(p)->t == T_ID || cur(p)->t == T_QID || cur(p)->t == T_STR) {
        if (is_col_cons_kw(p)) break;
        if (!has_type) ts = cur(p)->s;
        has_type = true;
        te = cur(p)->s + cur(p)->n;
        p->i++;
    }
    if (has_type && op(p, "(")) {
        p->i++;
        for (int k = 0; k < 2; k++) {
            if (!accept_op(p, "+")) accept_op(p, "-");
            if (cur(p)->t != T_NUM && cur(p)->t != T_ID) { perr(p, "syntax error"); free(name); return false; }
            p->i++;
            if (!accept_op(p, ",")) break;
        }
        if (!op(p, ")")) { perr(p, "syntax error"); free(name); return false; }
        te = cur(p)->s + 1;
        p->i++;
    }
    sq_col c = { name, has_type ? column_type(p->src, ts, te - ts) : pw_dup(""), false, false, false, 0 };
    c.aff = col_affinity(c.type);
    sq_col *v = realloc(t->cols, sizeof *v * (t->ncols + 1));
    if (v == nullptr) abort();
    t->cols = v;
    t->cols[t->ncols++] = c;
    const int ci = (int)t->ncols - 1;
    for (;;) {
        if (accept_kw(p, "CONSTRAINT")) { if (!name_tok(p, nullptr, nullptr)) return false; continue; }
        if (accept_kw(p, "PRIMARY")) {
            if (!expect_kw(p, "KEY")) return false;
            bool desc = false;
            if (accept_kw(p, "DESC")) desc = true;
            else accept_kw(p, "ASC");
            conflict_clause(p);
            const bool autoinc = accept_kw(p, "AUTOINCREMENT");
            for (size_t k = 0; k < t->ncols; k++) {
                if (t->cols[k].pk) { perr(p, "table has more than one primary key"); return false; }
            }
            t->cols[ci].pk = true;
            if (!t->without_rowid && strcmp(t->cols[ci].type, "INTEGER") == 0 && !desc) {
                t->ipk = ci;
            } else {
                if (autoinc) { perr(p, "AUTOINCREMENT is only allowed on an INTEGER PRIMARY KEY"); return false; }
                pw_strv cols = {0};
                pw_strv_push(&cols, pw_lower(t->cols[ci].name));
                constraint_index(t, cols);
            }
            add_uniq(t, ci, true);
            continue;
        }
        if (accept_kw(p, "NOT")) {
            if (!expect_kw(p, "NULL")) return false;
            conflict_clause(p);
            t->cols[ci].notnull = true;
            continue;
        }
        if (accept_kw(p, "NULL")) { conflict_clause(p); continue; }
        if (accept_kw(p, "UNIQUE")) {
            conflict_clause(p);
            pw_strv cols = {0};
            pw_strv_push(&cols, pw_lower(t->cols[ci].name));
            constraint_index(t, cols);
            add_uniq(t, ci, false);
            continue;
        }
        if (accept_kw(p, "CHECK")) { if (!skip_parens(p)) return false; continue; }
        if (accept_kw(p, "DEFAULT")) {
            if (op(p, "(")) { if (!skip_parens(p)) return false; continue; }
            if (!accept_op(p, "+")) accept_op(p, "-");
            const tok *d = cur(p);
            if (d->t == T_NUM || d->t == T_STR || d->t == T_BLOB || d->t == T_ID || d->t == T_QID) { p->i++; continue; }
            perr(p, "syntax error");
            return false;
        }
        if (accept_kw(p, "COLLATE")) { if (!name_tok(p, nullptr, nullptr)) return false; continue; }
        if (kw(p, "REFERENCES")) {
            fk_pending fk = {0};
            pw_strv_push(&fk.from, pw_lower(t->cols[ci].name));
            if (!fk_clause(p, &fk)) { free_fkp(&fk); return false; }
            if (fk.to.n > 1) {
                char msg[200];
                snprintf(msg, sizeof msg, "foreign key on %s should reference only one column of table %s",
                         t->cols[ci].name, fk.table);
                free_fkp(&fk);
                perr(p, msg);
                return false;
            }
            add_fk(t, &fk, p->db, p);
            free_fkp(&fk);
            if (p->failed) return false;
            continue;
        }
        if (kw(p, "GENERATED") || kw(p, "AS")) {
            if (accept_kw(p, "GENERATED")) { if (!expect_kw(p, "ALWAYS")) return false; }
            if (!expect_kw(p, "AS")) return false;
            if (!skip_parens(p)) return false;
            if (!accept_kw(p, "STORED")) accept_kw(p, "VIRTUAL");
            t->cols[ci].hidden = true;
            continue;
        }
        break;
    }
    return true;
}

static bool table_constraint(ps *p, sq_table *t) {
    if (accept_kw(p, "CONSTRAINT")) { if (!name_tok(p, nullptr, nullptr)) return false; }
    if (accept_kw(p, "PRIMARY")) {
        if (!expect_kw(p, "KEY")) return false;
        pw_strv cols = {0};
        bool desc = false;
        if (!col_list(p, &cols, &desc, false)) { pw_strv_free(&cols); return false; }
        conflict_clause(p);
        accept_kw(p, "AUTOINCREMENT");
        for (size_t k = 0; k < t->ncols; k++) {
            if (t->cols[k].pk) { pw_strv_free(&cols); perr(p, "table has more than one primary key"); return false; }
        }
        for (size_t k = 0; k < cols.n; k++) {
            const int ci = col_index(t, cols.v[k]);
            if (ci < 0) {
                char msg[200];
                snprintf(msg, sizeof msg, "no such column: %s", cols.v[k]);
                pw_strv_free(&cols);
                perr(p, msg);
                return false;
            }
            t->cols[ci].pk = true;
        }
        const int c0 = col_index(t, cols.v[0]);
        if (cols.n == 1) add_uniq(t, c0, true);
        if (cols.n == 1 && !t->without_rowid && strcmp(t->cols[c0].type, "INTEGER") == 0) {
            t->ipk = c0;
            pw_strv_free(&cols);
        } else {
            constraint_index(t, cols);
        }
        (void)desc;
        return true;
    }
    if (accept_kw(p, "UNIQUE")) {
        pw_strv cols = {0};
        if (!col_list(p, &cols, nullptr, false)) { pw_strv_free(&cols); return false; }
        conflict_clause(p);
        for (size_t k = 0; k < cols.n; k++) {
            if (col_index(t, cols.v[k]) < 0) {
                char msg[200];
                snprintf(msg, sizeof msg, "no such column: %s", cols.v[k]);
                pw_strv_free(&cols);
                perr(p, msg);
                return false;
            }
        }
        if (cols.n == 1) add_uniq(t, col_index(t, cols.v[0]), false);
        constraint_index(t, cols);
        return true;
    }
    if (accept_kw(p, "CHECK")) { if (!skip_parens(p)) return false; conflict_clause(p); return true; }
    if (accept_kw(p, "FOREIGN")) {
        if (!expect_kw(p, "KEY")) return false;
        fk_pending fk = {0};
        if (!col_list(p, &fk.from, nullptr, false)) { free_fkp(&fk); return false; }
        for (size_t k = 0; k < fk.from.n; k++) {
            if (col_index(t, fk.from.v[k]) < 0) {
                char msg[200];
                snprintf(msg, sizeof msg, "unknown column \"%s\" in foreign key definition", fk.from.v[k]);
                free_fkp(&fk);
                perr(p, msg);
                return false;
            }
        }
        if (!fk_clause(p, &fk)) { free_fkp(&fk); return false; }
        add_fk(t, &fk, p->db, p);
        free_fkp(&fk);
        return !p->failed;
    }
    perr(p, "syntax error");
    return false;
}

static void free_table(sq_table *t) {
    for (size_t i = 0; i < t->ncols; i++) { free(t->cols[i].name); free(t->cols[i].type); }
    for (size_t i = 0; i < t->nfks; i++) { free(t->fks[i].from); free(t->fks[i].to_table); free(t->fks[i].to_col); }
    for (size_t i = 0; i < t->nidx; i++) { free(t->idx[i].name); pw_strv_free(&t->idx[i].cols); }
    for (size_t i = 0; i < t->nuq; i++) pw_strv_free(&t->uq[i].vals);
    free(t->cols);
    free(t->fks);
    free(t->idx);
    free(t->uq);
    free(t->name);
    free(t->sql);
    *t = (sq_table){0};
}

/* Parses "( columns, constraints ) [options]" after the table name token.
 * name_tok_start is where the stored "CREATE TABLE " text resumes. */
static bool parse_table_body(ps *p, sq_table *t, size_t name_start) {
    t->ipk = -1;
    /* WITHOUT ROWID changes how PRIMARY KEY behaves: look ahead for it. */
    {
        int depth = 0;
        size_t j = p->i;
        for (; j < p->n && p->v[j].t != T_SEMI && p->v[j].t != T_EOF; j++) {
            if (op_at(p, j, "(")) depth++;
            else if (op_at(p, j, ")")) { depth--; if (depth == 0) { j++; break; } }
        }
        for (; j < p->n && p->v[j].t != T_SEMI && p->v[j].t != T_EOF; j++) {
            if (kw_at(p, j, "WITHOUT") && kw_at(p, j + 1, "ROWID")) t->without_rowid = true;
        }
    }
    if (!expect_op(p, "(")) return false;
    bool in_cons = false;
    size_t last_col_end = 0;
    for (;;) {
        const bool cons = kw(p, "CONSTRAINT") || kw(p, "PRIMARY") || kw(p, "UNIQUE") || kw(p, "CHECK") || kw(p, "FOREIGN");
        if (cons) in_cons = true;
        if (!in_cons) {
            if (!add_column(p, t)) return false;
            last_col_end = p->v[p->i - 1].s + p->v[p->i - 1].n;
        } else if (!table_constraint(p, t)) {
            return false;
        }
        if (accept_op(p, ",")) continue;
        if (op(p, ")")) break;
        if (in_cons) continue;   /* table constraints may omit commas */
        perr(p, "syntax error");
        return false;
    }
    size_t end = cur(p)->s + 1;
    p->i++;
    for (;;) {
        if (accept_kw(p, "WITHOUT")) {
            if (!expect_kw(p, "ROWID")) return false;
            end = p->v[p->i - 1].s + p->v[p->i - 1].n;
        } else if (accept_kw(p, "STRICT")) {
            end = p->v[p->i - 1].s + p->v[p->i - 1].n;
        } else {
            break;
        }
        if (!accept_op(p, ",")) break;
    }
    if (cur(p)->t != T_SEMI && cur(p)->t != T_EOF) { perr(p, "syntax error"); return false; }
    if (t->without_rowid) {
        bool any = false;
        for (size_t k = 0; k < t->ncols; k++) {
            if (t->cols[k].pk) { any = true; t->cols[k].notnull = true; }
        }
        if (!any) {
            char msg[200];
            snprintf(msg, sizeof msg, "PRIMARY KEY missing on table %s", t->name);
            perr(p, msg);
            return false;
        }
    }
    pw_buf b = {0};
    pw_buf_puts(&b, "CREATE TABLE ");
    pw_buf_put(&b, p->src + name_start, end - name_start);
    t->sql = pw_buf_take(&b, nullptr);
    t->add_col_off = 13 + (last_col_end - name_start);
    return true;
}

/* ------------------------------------------------------------------ */
/* Statement execution against the model                               */
/* ------------------------------------------------------------------ */

static void warn_skip(ps *p, const char *what) {
    fprintf(stderr, "bsm: %s: %s not modelled, statement skipped\n", p->db->file, what);
}

/* [schema .] name */
static bool qualified_name(ps *p, char **name, const tok **t) {
    char *a;
    const tok *ta;
    if (!name_tok(p, &a, &ta)) return false;
    if (accept_op(p, ".")) {
        free(a);
        return name_tok(p, name, t);
    }
    *name = a;
    if (t) *t = ta;
    return true;
}

static void skip_stmt(ps *p) {
    while (cur(p)->t != T_SEMI && cur(p)->t != T_EOF) p->i++;
}

static bool exec_create_table(ps *p, bool temp) {
    bool ifne = false;
    if (accept_kw(p, "IF")) {
        if (!expect_kw(p, "NOT") || !expect_kw(p, "EXISTS")) return false;
        ifne = true;
    }
    char *name;
    const tok *nt;
    if (!qualified_name(p, &name, &nt)) return false;
    if (pw_startswith(name, "sqlite_") || strncasecmp(name, "sqlite_", 7) == 0) {
        free(name);
        perr(p, "object name reserved for internal use");
        return false;
    }
    if (find_table(p->db, name)) {
        if (ifne) { free(name); skip_stmt(p); return true; }
        char msg[200];
        snprintf(msg, sizeof msg, "table %s already exists", name);
        free(name);
        perr(p, msg);
        return false;
    }
    if (accept_kw(p, "AS")) {
        free(name);
        warn_skip(p, "CREATE TABLE ... AS SELECT");
        skip_stmt(p);
        return true;
    }
    sq_table t = {0};
    t.name = name;
    t.temp = temp;
    t.rows_known = true;
    t.next_rowid = 1;
    if (!parse_table_body(p, &t, nt->s)) { free_table(&t); return false; }
    sq_table *v = realloc(p->db->t, sizeof *v * (p->db->n + 1));
    if (v == nullptr) abort();
    p->db->t = v;
    p->db->t[p->db->n++] = t;
    return true;
}

static bool index_exists(sq_db *db, const char *name) {
    for (size_t i = 0; i < db->n; i++) {
        for (size_t k = 0; k < db->t[i].nidx; k++) {
            if (strcasecmp(db->t[i].idx[k].name, name) == 0) return true;
        }
    }
    return false;
}

static bool exec_create_index(ps *p) {
    bool ifne = false;
    if (accept_kw(p, "IF")) {
        if (!expect_kw(p, "NOT") || !expect_kw(p, "EXISTS")) return false;
        ifne = true;
    }
    char *name, *tname;
    if (!qualified_name(p, &name, nullptr)) return false;
    if (!expect_kw(p, "ON")) { free(name); return false; }
    if (!name_tok(p, &tname, nullptr)) { free(name); return false; }
    pw_strv cols = {0};
    if (!col_list(p, &cols, nullptr, true)) { free(name); free(tname); pw_strv_free(&cols); return false; }
    if (accept_kw(p, "WHERE")) skip_stmt(p);
    sq_table *t = find_table(p->db, tname);
    free(tname);
    if (t == nullptr) {
        pw_strv_free(&cols);
        char msg[200];
        snprintf(msg, sizeof msg, "no such table: %s", name);
        free(name);
        perr(p, msg);
        return false;
    }
    if (index_exists(p->db, name) || find_table(p->db, name)) {
        pw_strv_free(&cols);
        if (ifne) { free(name); return true; }
        char msg[200];
        snprintf(msg, sizeof msg, "index %s already exists", name);
        free(name);
        perr(p, msg);
        return false;
    }
    for (size_t k = 0; k < cols.n; k++) {
        if (cols.v[k][0] && col_index(t, cols.v[k]) < 0) {
            char msg[200];
            snprintf(msg, sizeof msg, "no such column: %s", cols.v[k]);
            pw_strv_free(&cols);
            free(name);
            perr(p, msg);
            return false;
        }
    }
    add_index(t, name, cols, false);
    return true;
}

/* Normalised key of a literal value token, or nullptr (not a literal / NULL). */
static char *literal_key(ps *p, size_t from, size_t to, char aff, bool *is_null) {
    *is_null = false;
    size_t i = from;
    bool neg = false;
    if (to - from == 2 && (op_at(p, i, "-") || op_at(p, i, "+"))) { neg = op_at(p, i, "-"); i++; }
    if (to - i != 1) return nullptr;
    const tok *t = &p->v[i];
    if (t->t == T_ID && t->n == 4 && strncasecmp(p->src + t->s, "NULL", 4) == 0) { *is_null = true; return nullptr; }
    char *txt = nullptr;
    bool num = false;
    if (t->t == T_NUM) { txt = pw_dupn(p->src + t->s, t->n); num = true; }
    else if (t->t == T_STR) txt = dequote(p->src + t->s, t->n);
    else return nullptr;
    if (!num && (aff == 'I' || aff == 'R' || aff == 'N')) {
        char *e;
        strtod(txt, &e);
        if (txt[0] && *e == 0 && !pw_isspace((unsigned char)txt[0])) num = true;
    }
    char *key;
    if (num) {
        const double d = strtod(txt, nullptr) * (neg ? -1 : 1);
        key = pw_fmt("n:%.17g", d);
    } else {
        key = pw_fmt("s:%s", txt);
    }
    free(txt);
    return key;
}

static bool exec_insert(ps *p, bool replace_kw) {
    char conflict = replace_kw ? 'R' : 'A';
    if (accept_kw(p, "OR")) {
        if (accept_kw(p, "REPLACE")) conflict = 'R';
        else if (accept_kw(p, "IGNORE")) conflict = 'I';
        else if (accept_kw(p, "ROLLBACK") || accept_kw(p, "ABORT") || accept_kw(p, "FAIL")) conflict = 'A';
        else { perr(p, "syntax error"); return false; }
    }
    if (!expect_kw(p, "INTO")) return false;
    char *tname;
    if (!qualified_name(p, &tname, nullptr)) return false;
    if (accept_kw(p, "AS")) { if (!name_tok(p, nullptr, nullptr)) { free(tname); return false; } }
    sq_table *t = find_table(p->db, tname);
    if (t == nullptr) {
        char msg[200];
        snprintf(msg, sizeof msg, "no such table: %s", tname);
        free(tname);
        perr(p, msg);
        return false;
    }
    free(tname);
    int map[512];
    size_t nmap = 0;
    if (op(p, "(")) {
        pw_strv cols = {0};
        if (!col_list(p, &cols, nullptr, false)) { pw_strv_free(&cols); return false; }
        for (size_t k = 0; k < cols.n && nmap < 512; k++) {
            const int ci = col_index(t, cols.v[k]);
            if (ci < 0) {
                char msg[200];
                snprintf(msg, sizeof msg, "table %s has no column named %s", t->name, cols.v[k]);
                pw_strv_free(&cols);
                perr(p, msg);
                return false;
            }
            map[nmap++] = ci;
        }
        pw_strv_free(&cols);
    } else {
        for (size_t k = 0; k < t->ncols && nmap < 512; k++) {
            if (!t->cols[k].hidden) map[nmap++] = (int)k;
        }
    }
    if (accept_kw(p, "DEFAULT")) {
        if (!expect_kw(p, "VALUES")) return false;
        if (t->rows_known) t->rows++;
        return true;
    }
    if (!accept_kw(p, "VALUES")) {
        warn_skip(p, "INSERT ... SELECT");
        t->rows_known = false;
        skip_stmt(p);
        return true;
    }
    for (;;) {
        if (!expect_op(p, "(")) return false;
        size_t starts[512], ends[512], nv = 0;
        for (;;) {
            const size_t st = p->i;
            skip_expr(p);
            if (nv < 512) { starts[nv] = st; ends[nv] = p->i; nv++; }
            if (accept_op(p, ",")) continue;
            if (!expect_op(p, ")")) return false;
            break;
        }
        if (nv != nmap) {
            char msg[200];
            if (nmap == t->ncols) snprintf(msg, sizeof msg, "table %s has %zu columns but %zu values were supplied", t->name, nmap, nv);
            else snprintf(msg, sizeof msg, "%zu values for %zu columns", nv, nmap);
            perr(p, msg);
            return false;
        }
        bool skip_row = false, replaced = false;
        char *keys[512] = {0};
        for (size_t k = 0; k < nv; k++) {
            bool is_null;
            const int ci = map[k];
            keys[k] = literal_key(p, starts[k], ends[k], t->cols[ci].aff, &is_null);
            if (is_null && t->cols[ci].notnull && ci != t->ipk) {
                if (conflict == 'I') { skip_row = true; continue; }
                char msg[200];
                snprintf(msg, sizeof msg, "NOT NULL constraint failed: %s.%s", t->name, t->cols[ci].name);
                for (size_t z = 0; z < nv; z++) free(keys[z]);
                perr(p, msg);
                return false;
            }
        }
        for (size_t u = 0; u < t->nuq && !skip_row; u++) {
            const char *key = nullptr;
            for (size_t k = 0; k < nv; k++) {
                if (map[k] == t->uq[u].col) key = keys[k];
            }
            if (key == nullptr) continue;
            if (pw_strv_has(&t->uq[u].vals, key)) {
                if (conflict == 'I') skip_row = true;
                else if (conflict == 'R') replaced = true;
                else {
                    char msg[200];
                    snprintf(msg, sizeof msg, "%s constraint failed: %s.%s", t->uq[u].is_pk ? "UNIQUE" : "UNIQUE",
                             t->name, t->cols[t->uq[u].col].name);
                    for (size_t z = 0; z < nv; z++) free(keys[z]);
                    perr(p, msg);
                    return false;
                }
            }
        }
        if (!skip_row) {
            for (size_t u = 0; u < t->nuq; u++) {
                for (size_t k = 0; k < nv; k++) {
                    if (map[k] == t->uq[u].col && keys[k] && !pw_strv_has(&t->uq[u].vals, keys[k]))
                        pw_strv_push(&t->uq[u].vals, pw_dup(keys[k]));
                }
            }
            if (!replaced && t->rows_known) t->rows++;
        }
        for (size_t z = 0; z < nv; z++) free(keys[z]);
        if (accept_op(p, ",")) continue;
        break;
    }
    if (kw(p, "ON") || kw(p, "RETURNING")) skip_stmt(p);
    return true;
}

static void drop_table_at(sq_db *db, size_t i) {
    free_table(&db->t[i]);
    memmove(db->t + i, db->t + i + 1, sizeof *db->t * (db->n - i - 1));
    db->n--;
}

static bool exec_drop(ps *p) {
    const bool is_table = accept_kw(p, "TABLE");
    const bool is_index = !is_table && accept_kw(p, "INDEX");
    if (!is_table && !is_index) {
        if (accept_kw(p, "VIEW") || accept_kw(p, "TRIGGER")) { skip_stmt(p); return true; }
        perr(p, "syntax error");
        return false;
    }
    bool ife = false;
    if (accept_kw(p, "IF")) { if (!expect_kw(p, "EXISTS")) return false; ife = true; }
    char *name;
    if (!qualified_name(p, &name, nullptr)) return false;
    if (is_table) {
        for (size_t i = 0; i < p->db->n; i++) {
            if (strcasecmp(p->db->t[i].name, name) == 0) { drop_table_at(p->db, i); free(name); return true; }
        }
    } else {
        for (size_t i = 0; i < p->db->n; i++) {
            sq_table *t = &p->db->t[i];
            for (size_t k = 0; k < t->nidx; k++) {
                if (strcasecmp(t->idx[k].name, name) == 0 && !t->idx[k].constraint) {
                    free(t->idx[k].name);
                    pw_strv_free(&t->idx[k].cols);
                    memmove(t->idx + k, t->idx + k + 1, sizeof *t->idx * (t->nidx - k - 1));
                    t->nidx--;
                    free(name);
                    return true;
                }
            }
        }
    }
    if (ife) { free(name); return true; }
    char msg[200];
    snprintf(msg, sizeof msg, "no such %s: %s", is_table ? "table" : "index", name);
    free(name);
    perr(p, msg);
    return false;
}

static bool exec_alter(ps *p) {
    if (!expect_kw(p, "TABLE")) return false;
    char *name;
    if (!qualified_name(p, &name, nullptr)) return false;
    sq_table *t = find_table(p->db, name);
    if (t == nullptr) {
        char msg[200];
        snprintf(msg, sizeof msg, "no such table: %s", name);
        free(name);
        perr(p, msg);
        return false;
    }
    free(name);
    if (!accept_kw(p, "ADD")) {
        warn_skip(p, "ALTER TABLE other than ADD COLUMN");
        skip_stmt(p);
        return true;
    }
    accept_kw(p, "COLUMN");
    const size_t def_start = cur(p)->s;
    const size_t nidx_before = t->nidx;
    if (!add_column(p, t)) return false;
    if (t->nidx != nidx_before) { perr(p, "Cannot add a UNIQUE column"); return false; }
    if (t->cols[t->ncols - 1].pk) { perr(p, "Cannot add a PRIMARY KEY column"); return false; }
    size_t def_end = p->v[p->i - 1].s + p->v[p->i - 1].n;
    if (cur(p)->t != T_SEMI && cur(p)->t != T_EOF) { perr(p, "syntax error"); return false; }
    /* sqlite_schema.sql gets ", <column-def>" spliced in after the last
     * existing column definition. */
    pw_buf b = {0};
    pw_buf_put(&b, t->sql, t->add_col_off);
    pw_buf_puts(&b, ", ");
    pw_buf_put(&b, p->src + def_start, def_end - def_start);
    const size_t new_off = b.n;
    pw_buf_puts(&b, t->sql + t->add_col_off);
    free(t->sql);
    t->sql = pw_buf_take(&b, nullptr);
    t->add_col_off = new_off;
    return true;
}

static bool exec_delete(ps *p) {
    if (!expect_kw(p, "FROM")) return false;
    char *name;
    if (!qualified_name(p, &name, nullptr)) return false;
    sq_table *t = find_table(p->db, name);
    if (t == nullptr) {
        char msg[200];
        snprintf(msg, sizeof msg, "no such table: %s", name);
        free(name);
        perr(p, msg);
        return false;
    }
    free(name);
    if (cur(p)->t == T_SEMI || cur(p)->t == T_EOF) {
        t->rows = 0;
        t->rows_known = true;
        for (size_t u = 0; u < t->nuq; u++) pw_strv_free(&t->uq[u].vals);
        return true;
    }
    warn_skip(p, "DELETE ... WHERE");
    t->rows_known = false;
    skip_stmt(p);
    return true;
}

/* CREATE [TEMP] TRIGGER ... BEGIN ... END: skip to the END that closes it. */
static void skip_trigger(ps *p) {
    int depth = 0;
    while (cur(p)->t != T_EOF) {
        if (kw(p, "CASE")) depth++;
        else if (kw(p, "BEGIN") && depth == 0) depth = 1;
        else if (kw(p, "END")) {
            depth--;
            if (depth <= 0) { p->i++; return; }
        }
        p->i++;
    }
}

/* Runs one statement; false on an error SQLite would raise. */
static bool exec_stmt(ps *p) {
    if (cur(p)->t == T_SEMI || cur(p)->t == T_EOF) return true;
    if (accept_kw(p, "EXPLAIN")) {
        if (accept_kw(p, "QUERY")) expect_kw(p, "PLAN");
        skip_stmt(p);
        return !p->failed;
    }
    if (accept_kw(p, "CREATE")) {
        const bool temp = accept_kw(p, "TEMP") || accept_kw(p, "TEMPORARY");
        if (accept_kw(p, "TABLE")) return exec_create_table(p, temp);
        if (accept_kw(p, "UNIQUE")) { if (!expect_kw(p, "INDEX")) return false; return exec_create_index(p); }
        if (accept_kw(p, "INDEX")) return exec_create_index(p);
        if (accept_kw(p, "VIEW")) { skip_stmt(p); return true; }
        if (accept_kw(p, "TRIGGER")) { skip_trigger(p); return true; }
        if (accept_kw(p, "VIRTUAL")) { warn_skip(p, "CREATE VIRTUAL TABLE"); skip_stmt(p); return true; }
        perr(p, "syntax error");
        return false;
    }
    if (accept_kw(p, "INSERT")) return exec_insert(p, false);
    if (accept_kw(p, "REPLACE")) return exec_insert(p, true);
    if (accept_kw(p, "DROP")) return exec_drop(p);
    if (accept_kw(p, "ALTER")) return exec_alter(p);
    if (accept_kw(p, "DELETE")) return exec_delete(p);
    static const char *const ignored[] = { "BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE",
                                           "PRAGMA", "ANALYZE", "VACUUM", "REINDEX", "SELECT", "VALUES",
                                           "UPDATE", "WITH", "ATTACH", "DETACH" };
    for (size_t k = 0; k < sizeof ignored / sizeof ignored[0]; k++) {
        if (kw(p, ignored[k])) { skip_stmt(p); return true; }
    }
    perr(p, "syntax error");
    return false;
}

/* executescript() equivalent. Returns false if SQLite would raise. */
static bool run_script(sq_db *db, const char *src, size_t len) {
    tokv tv = {0};
    if (!tokenize(src, len, &tv)) {
        free(tv.v);
        snprintf(db->err, sizeof db->err, "unrecognized token");
        return false;
    }
    ps p = { src, tv.v, tv.n, 0, db, false };
    while (cur(&p)->t != T_EOF) {
        if (!exec_stmt(&p)) { free(tv.v); return false; }
        if (cur(&p)->t == T_SEMI) p.i++;
        else if (cur(&p)->t != T_EOF) { perr(&p, "syntax error"); free(tv.v); return false; }
    }
    free(tv.v);
    return true;
}

/* ------------------------------------------------------------------ */
/* Database file reader                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *d;
    size_t len;
    uint32_t page_size, usable, npages;
    uint32_t enc;
    const char *path;
} sq_file;

[[noreturn]] static void corrupt(const sq_file *f, const char *why) {
    pw_die("sqlite3.DatabaseError: database disk image is malformed (%s: %s)", f->path, why);
}

static uint32_t be16(const uint8_t *p) { return (uint32_t)p[0] << 8 | p[1]; }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static const uint8_t *page_at(const sq_file *f, uint32_t pg) {
    if (pg < 1 || pg > f->npages) corrupt(f, "page number out of range");
    return f->d + (size_t)(pg - 1) * f->page_size;
}

static uint64_t varint(const sq_file *f, const uint8_t *p, const uint8_t *end, size_t *used) {
    uint64_t v = 0;
    for (size_t i = 0; i < 9; i++) {
        if (p + i >= end) corrupt(f, "truncated varint");
        if (i == 8) { v = (v << 8) | p[i]; *used = 9; return v; }
        v = (v << 7) | (p[i] & 0x7F);
        if (!(p[i] & 0x80)) { *used = i + 1; return v; }
    }
    return v;
}

/* Full payload of a cell (local part plus overflow chain). */
static uint8_t *cell_payload(const sq_file *f, const uint8_t *cell, const uint8_t *pend, uint64_t plen, bool table_leaf) {
    const uint64_t U = f->usable;
    const uint64_t X = table_leaf ? U - 35 : ((U - 12) * 64 / 255) - 23;
    const uint64_t M = ((U - 12) * 32 / 255) - 23;
    uint64_t local = plen;
    if (plen > X) {
        const uint64_t K = M + ((plen - M) % (U - 4));
        local = K <= X ? K : M;
    }
    if (plen > (uint64_t)64 << 20) corrupt(f, "payload too large");
    uint8_t *out = malloc(plen ? plen : 1);
    if (out == nullptr) abort();
    if (cell + local > pend) corrupt(f, "cell overflows page");
    memcpy(out, cell, local);
    uint64_t got = local;
    if (got < plen) {
        if (cell + local + 4 > pend) corrupt(f, "missing overflow pointer");
        uint32_t ov = be32(cell + local);
        size_t hops = 0;
        while (got < plen) {
            if (ov == 0 || ++hops > f->npages) corrupt(f, "broken overflow chain");
            const uint8_t *pg = page_at(f, ov);
            const uint64_t take = (plen - got) < (U - 4) ? (plen - got) : (U - 4);
            memcpy(out + got, pg + 4, take);
            got += take;
            ov = be32(pg);
        }
    }
    return out;
}

typedef struct {
    uint8_t **payloads;
    size_t *lens;
    size_t n, cap;
    uint64_t count;
} walk_out;

static void walk_push(walk_out *w, uint8_t *p, size_t n) {
    if (w->n == w->cap) {
        w->cap = w->cap ? w->cap * 2 : 16;
        w->payloads = realloc(w->payloads, sizeof *w->payloads * w->cap);
        w->lens = realloc(w->lens, sizeof *w->lens * w->cap);
        if (w->payloads == nullptr || w->lens == nullptr) abort();
    }
    w->payloads[w->n] = p;
    w->lens[w->n++] = n;
}

/* Walks a b-tree; counts entries and optionally collects table-leaf payloads. */
static void walk(const sq_file *f, uint32_t pg, walk_out *w, bool collect, int depth) {
    if (depth > 64) corrupt(f, "b-tree too deep");
    const uint8_t *page = page_at(f, pg);
    const uint8_t *h = page + (pg == 1 ? 100 : 0);
    const uint8_t *pend = page + f->usable;
    const uint8_t type = h[0];
    const uint32_t ncell = be16(h + 3);
    const bool interior = type == 0x02 || type == 0x05;
    if (type != 0x02 && type != 0x05 && type != 0x0A && type != 0x0D) corrupt(f, "bad page type");
    const uint8_t *ptrs = h + (interior ? 12 : 8);
    if (ptrs + 2 * (size_t)ncell > pend) corrupt(f, "cell pointer array overflows page");
    for (uint32_t c = 0; c < ncell; c++) {
        const uint32_t off = be16(ptrs + 2 * c);
        if (off >= f->usable) corrupt(f, "cell offset out of range");
        const uint8_t *cell = page + off;
        size_t u;
        if (type == 0x05) {
            walk(f, be32(cell), w, collect, depth + 1);
        } else if (type == 0x0D) {
            const uint64_t plen = varint(f, cell, pend, &u);
            size_t u2;
            (void)varint(f, cell + u, pend, &u2);
            w->count++;
            if (collect) walk_push(w, cell_payload(f, cell + u + u2, pend, plen, true), (size_t)plen);
        } else if (type == 0x02) {
            walk(f, be32(cell), w, collect, depth + 1);
            w->count++;
        } else {
            w->count++;
        }
    }
    if (interior) walk(f, be32(h + 8), w, collect, depth + 1);
}

typedef struct {
    int t;   /* 0 null, 1 int, 2 float, 3 text, 4 blob */
    int64_t i;
    char *s;
} sq_val;

static char *utf16_to_utf8(const uint8_t *p, size_t n, bool be) {
    pw_buf b = {0};
    pw_buf_put(&b, "", 0);
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint32_t cp = be ? (uint32_t)p[i] << 8 | p[i + 1] : (uint32_t)p[i + 1] << 8 | p[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 3 < n) {
            const uint32_t lo = be ? (uint32_t)p[i + 2] << 8 | p[i + 3] : (uint32_t)p[i + 3] << 8 | p[i + 2];
            if (lo >= 0xDC00 && lo <= 0xDFFF) { cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00); i += 2; }
        }
        if (cp < 0x80) pw_buf_putc(&b, (int)cp);
        else if (cp < 0x800) { pw_buf_putc(&b, (int)(0xC0 | (cp >> 6))); pw_buf_putc(&b, (int)(0x80 | (cp & 0x3F))); }
        else if (cp < 0x10000) {
            pw_buf_putc(&b, (int)(0xE0 | (cp >> 12)));
            pw_buf_putc(&b, (int)(0x80 | ((cp >> 6) & 0x3F)));
            pw_buf_putc(&b, (int)(0x80 | (cp & 0x3F)));
        } else {
            pw_buf_putc(&b, (int)(0xF0 | (cp >> 18)));
            pw_buf_putc(&b, (int)(0x80 | ((cp >> 12) & 0x3F)));
            pw_buf_putc(&b, (int)(0x80 | ((cp >> 6) & 0x3F)));
            pw_buf_putc(&b, (int)(0x80 | (cp & 0x3F)));
        }
    }
    return pw_buf_take(&b, nullptr);
}

/* Decodes the first ncol columns of a record. */
static void record_vals(const sq_file *f, const uint8_t *rec, size_t n, sq_val *vals, size_t ncol) {
    const uint8_t *end = rec + n;
    size_t u;
    const uint64_t hsz = varint(f, rec, end, &u);
    if (hsz > n) corrupt(f, "record header too large");
    const uint8_t *hp = rec + u, *hend = rec + hsz, *body = rec + hsz;
    for (size_t c = 0; c < ncol; c++) {
        vals[c] = (sq_val){0};
        if (hp >= hend) continue;
        const uint64_t st = varint(f, hp, hend, &u);
        hp += u;
        size_t sz = 0;
        if (st >= 1 && st <= 6) {
            static const size_t L[] = { 0, 1, 2, 3, 4, 6, 8 };
            sz = L[st];
            if (body + sz > end) corrupt(f, "record body overflow");
            int64_t v = (body[0] & 0x80) ? -1 : 0;
            for (size_t k = 0; k < sz; k++) v = (int64_t)((uint64_t)v << 8 | body[k]);
            vals[c] = (sq_val){ 1, v, nullptr };
        } else if (st == 7) {
            sz = 8;
            vals[c].t = 2;
        } else if (st == 8 || st == 9) {
            vals[c] = (sq_val){ 1, (int64_t)(st - 8), nullptr };
        } else if (st >= 12) {
            sz = (size_t)((st - 12) / 2);
            if (body + sz > end) corrupt(f, "record body overflow");
            if (st & 1) {
                vals[c].t = 3;
                vals[c].s = f->enc == 1 ? pw_dupn((const char *)body, sz) : utf16_to_utf8(body, sz, f->enc == 3);
            } else {
                vals[c].t = 4;
            }
        }
        body += sz;
    }
}

typedef struct {
    char *type, *name, *tbl_name, *sql;
    uint32_t rootpage;
} schema_row;

/* ------------------------------------------------------------------ */
/* Records                                                             */
/* ------------------------------------------------------------------ */

static void sqlite_col_size(const char *type, long *sz, const char **kind) {
    static const struct { const char *k; long sz; const char *kind; } A[] = {
        {"INTEGER", 8, "integer"}, {"INT", 8, "int"}, {"REAL", 8, "real"}, {"FLOAT", 8, "float"},
        {"DOUBLE", 8, "double"}, {"NUMERIC", 8, "numeric"}, {"TEXT", 32, "text"},
        {"VARCHAR", 32, "varchar"}, {"BLOB", 64, "blob"},
    };
    char *up = pw_upper(type && type[0] ? type : "BLOB");
    for (size_t i = 0; i < sizeof A / sizeof A[0]; i++) {
        if (strstr(up, A[i].k)) { *sz = A[i].sz; *kind = A[i].kind; free(up); return; }
    }
    free(up);
    *sz = 16;
    *kind = "numeric";
}

static pj *field(const char *name, const char *type_name, long off, long size, long align, const char *kind,
                 const char *notes) {
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

static pj *symbol(const char *name, const char *fname, long size) {
    pj *s = pj_obj();
    pj_set(s, "name", pj_str(name));
    pj_set(s, "source_kind", pj_str("sqlite"));
    pj_set(s, "source_file", pj_str(fname));
    pj_set(s, "sym_type", pj_str("TABLE"));
    pj_set(s, "binding", pj_str("GLOBAL"));
    pj_set(s, "address", pj_int(0));
    pj_set(s, "size", pj_int(size));
    pj_set(s, "section", pj_str(""));
    return s;
}

static pj *record(const char *name, const char *fname, long total, pj *fields, pj *meta) {
    pj *r = pj_obj();
    pj_set(r, "name", pj_str(name));
    pj_set(r, "source_kind", pj_str("sqlite"));
    pj_set(r, "source_file", pj_str(fname));
    pj_set(r, "kind", pj_str("table"));
    pj_set(r, "total_size", pj_int(total));
    pj_set(r, "align", pj_int(1));
    pj_set(r, "padding_bytes", pj_int(0));
    pj_set(r, "fields", fields);
    pj_set(r, "metadata", meta);
    return r;
}

static void emit_table(const sq_table *t, const char *fname, pj *records, pj *symbols) {
    pj *fields = pj_arr();
    long off = 0;
    for (size_t i = 0; i < t->ncols; i++) {
        const sq_col *c = &t->cols[i];
        if (c->hidden) continue;
        long sz;
        const char *kind;
        sqlite_col_size(c->type, &sz, &kind);
        const char *notes = (c->pk && c->notnull) ? "PK, NOT NULL" : c->pk ? "PK" : c->notnull ? "NOT NULL" : "";
        pj_push(fields, field(c->name, c->type[0] ? c->type : "ANY", off, sz, 1, kind, notes));
        off += sz;
    }
    pj *fks = pj_arr();
    for (size_t i = 0; i < t->nfks; i++) {
        pj *fk = pj_obj();
        pj_set(fk, "from", pj_str(t->fks[i].from));
        pj_set(fk, "to_table", pj_str(t->fks[i].to_table));
        pj_set(fk, "to_col", pj_str(t->fks[i].to_col));
        pj_push(fks, fk);
    }
    pj *idx = pj_arr();
    for (size_t i = 0; i < t->nidx; i++) pj_push(idx, pj_str(t->idx[i].name));
    pj *meta = pj_obj();
    pj_set(meta, "row_count", pj_int(t->rows));
    pj_set(meta, "foreign_keys", fks);
    pj_set(meta, "indexes", idx);
    pj_set(meta, "ddl", pj_str(t->sql));
    pj_push(records, record(t->name, fname, off, fields, meta));
    pj_push(symbols, symbol(t->name, fname, off * (t->rows > 1 ? t->rows : 1)));
}

static bool listed(const sq_table *t) {
    /* sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' */
    return !t->temp && !(strlen(t->name) > 6 && strncasecmp(t->name, "sqlite", 6) == 0);
}

/* Regex fallback for scripts SQLite rejects. */
static void fallback(const char *txt, size_t n, const char *fname, pj *records, pj *symbols) {
    pw_re *re = pw_re_compile(
        "CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`\"\\[]?(\\w+)[`\"\\]]?\\s*\\((.*?)\\)\\s*;",
        PW_RE_I | PW_RE_S);
    pw_rm m;
    for (size_t p = 0; pw_re_next(re, txt, n, &p, &m);) {
        char *tname = pw_rm_dup(&m, 1, txt);
        pj *fields = pj_arr();
        long off = 0;
        pw_strv lines = pw_split_ch(txt + m.so[2], (size_t)(m.eo[2] - m.so[2]), ',');
        for (size_t i = 0; i < lines.n; i++) {
            pw_strv parts = pw_split_ws(lines.v[i], strlen(lines.v[i]), -1);
            if (parts.n == 0) { pw_strv_free(&parts); continue; }
            char *u0 = pw_upper(parts.v[0]);
            const bool skip = !strcmp(u0, "PRIMARY") || !strcmp(u0, "FOREIGN") || !strcmp(u0, "UNIQUE") ||
                              !strcmp(u0, "CHECK") || !strcmp(u0, "CONSTRAINT");
            free(u0);
            if (skip) { pw_strv_free(&parts); continue; }
            /* parts[0].strip("`\"[]") */
            const char *a = parts.v[0];
            size_t l = strlen(a);
            while (l && strchr("`\"[]", *a)) { a++; l--; }
            while (l && strchr("`\"[]", a[l - 1])) l--;
            char *cname = pw_dupn(a, l);
            const char *ctype = parts.n > 1 ? parts.v[1] : "BLOB";
            long sz;
            const char *kind;
            sqlite_col_size(ctype, &sz, &kind);
            pj_push(fields, field(cname, ctype, off, sz, 1, kind, ""));
            off += sz;
            free(cname);
            pw_strv_free(&parts);
        }
        pw_strv_free(&lines);
        pj_push(records, record(tname, fname, off, fields, pj_obj()));
        pj_push(symbols, symbol(tname, fname, off));
        free(tname);
    }
    pw_re_free(re);
}

static void free_db(sq_db *db) {
    for (size_t i = 0; i < db->n; i++) free_table(&db->t[i]);
    free(db->t);
    db->t = nullptr;
    db->n = 0;
}

static void ingest_sql(const char *path, const char *fname, pj *records, pj *symbols) {
    size_t n;
    char *txt = pw_read_text(path, &n);
    if (txt == nullptr) pw_die("FileNotFoundError: [Errno %d] %s: '%s'", errno, strerror(errno), path);
    sq_db db = { .file = fname };
    if (!run_script(&db, txt, n)) {
        free_db(&db);
        fallback(txt, n, fname, records, symbols);
        free(txt);
        return;
    }
    for (size_t i = 0; i < db.n; i++) {
        if (!listed(&db.t[i])) continue;
        if (!db.t[i].rows_known)
            fprintf(stderr, "bsm: %s: row count of %s is a lower bound (unmodelled statements)\n", fname, db.t[i].name);
        emit_table(&db.t[i], fname, records, symbols);
    }
    free_db(&db);
    free(txt);
}

static void ingest_db(const char *path, const char *fname, pj *records, pj *symbols) {
    size_t len;
    uint8_t *d = pw_slurp(path, &len);
    if (d == nullptr) pw_die("sqlite3.OperationalError: unable to open database file: '%s'", path);
    sq_file f = { d, len, 0, 0, 0, 1, path };
    if (len < 100 || memcmp(d, "SQLite format 3\0", 16) != 0) pw_die("sqlite3.DatabaseError: file is not a database: '%s'", path);
    f.page_size = be16(d + 16);
    if (f.page_size == 1) f.page_size = 65536;
    if (f.page_size < 512 || (f.page_size & (f.page_size - 1))) pw_die("sqlite3.DatabaseError: file is not a database: '%s'", path);
    f.usable = f.page_size - d[20];
    f.npages = (uint32_t)(len / f.page_size);
    f.enc = be32(d + 56);
    if (f.enc < 1 || f.enc > 3) f.enc = 1;
    walk_out w = {0};
    walk(&f, 1, &w, true, 0);
    schema_row *rows = calloc(w.n ? w.n : 1, sizeof *rows);
    if (rows == nullptr) abort();
    for (size_t i = 0; i < w.n; i++) {
        sq_val v[5];
        record_vals(&f, w.payloads[i], w.lens[i], v, 5);
        rows[i].type = v[0].s ? v[0].s : pw_dup("");
        rows[i].name = v[1].s ? v[1].s : pw_dup("");
        rows[i].tbl_name = v[2].s ? v[2].s : pw_dup("");
        rows[i].rootpage = v[3].t == 1 ? (uint32_t)v[3].i : 0;
        rows[i].sql = v[4].s;
        free(w.payloads[i]);
    }
    /* Rebuild the schema the way SQLite loads it: every CREATE in rowid order. */
    sq_db db = { .file = fname };
    for (size_t i = 0; i < w.n; i++) {
        if (rows[i].sql == nullptr) continue;
        const bool is_table = strcmp(rows[i].type, "table") == 0, is_index = strcmp(rows[i].type, "index") == 0;
        if (!is_table && !is_index) continue;
        tokv tv = {0};
        if (!tokenize(rows[i].sql, strlen(rows[i].sql), &tv)) { free(tv.v); continue; }
        ps p = { rows[i].sql, tv.v, tv.n, 0, &db, false };
        if (is_table) {
            if (kw(&p, "CREATE") && kw_at(&p, 1, "VIRTUAL")) {
                fprintf(stderr, "bsm: %s: virtual table %s not modelled\n", fname, rows[i].name);
                free(tv.v);
                continue;
            }
            p.i = 0;
            if (accept_kw(&p, "CREATE") && accept_kw(&p, "TABLE")) {
                const size_t before = db.n;
                exec_create_table(&p, false);
                if (db.n > before) {
                    sq_table *t = &db.t[db.n - 1];
                    free(t->sql);
                    t->sql = pw_dup(rows[i].sql);
                    t->rootpage = rows[i].rootpage;
                    walk_out c = {0};
                    if (t->rootpage) walk(&f, t->rootpage, &c, false, 0);
                    t->rows = (long)c.count;
                }
            }
        } else {
            if (accept_kw(&p, "CREATE")) {
                accept_kw(&p, "UNIQUE");
                if (accept_kw(&p, "INDEX")) exec_create_index(&p);
            }
        }
        free(tv.v);
    }
    for (size_t i = 0; i < db.n; i++) {
        if (listed(&db.t[i])) emit_table(&db.t[i], fname, records, symbols);
    }
    free_db(&db);
    for (size_t i = 0; i < w.n; i++) { free(rows[i].type); free(rows[i].name); free(rows[i].tbl_name); free(rows[i].sql); }
    free(rows);
    free(w.payloads);
    free(w.lens);
    free(d);
}

void pw_sqlite_ingest(const char *path, const char *fname, pj *records, pj *symbols) {
    char *suf = pw_path_suffix(path);
    char *low = pw_lower(suf);
    const bool sql = strcmp(low, ".sql") == 0;
    free(suf);
    free(low);
    if (sql) ingest_sql(path, fname, records, symbols);
    else ingest_db(path, fname, records, symbols);
}
