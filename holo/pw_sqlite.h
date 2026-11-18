/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* SQLite frontend without libsqlite3.
 *  - .db / .sqlite / .sqlite3 (or "SQLite format 3" magic): reads the file
 *    format directly: 100-byte header, sqlite_schema table b-tree (with
 *    overflow pages, UTF-8 / UTF-16 text), and per-table row counts by
 *    walking each table (or WITHOUT ROWID index) b-tree.
 *  - .sql: runs the DDL/DML script against an in-memory schema model
 *    (CREATE TABLE / INDEX, INSERT ... VALUES, DROP, ALTER TABLE ADD COLUMN,
 *    DELETE without WHERE); a script SQLite would reject falls back to the
 *    regex CREATE TABLE scan.
 * Column info (name, declared type, NOT NULL, PRIMARY KEY), foreign keys
 * and index lists follow what PRAGMA table_info / foreign_key_list /
 * index_list report. C23. */
#ifndef PW_SQLITE_H
#define PW_SQLITE_H

#include "pw_json.h"

/* Appends RecordIR / SymbolIR dicts for every table to records / symbols.
 * fname is the source file name stored in them. Exits on unreadable or
 * malformed database files. */
void pw_sqlite_ingest(const char *path, const char *fname, pj *records, pj *symbols);

#endif /* PW_SQLITE_H */
