/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Binary Semantics Machine: legacy inputs -> unified semantic IR -> a
 * WebAssembly 1.0 module (.holo.wasm) with content-addressed holo.* custom
 * sections, and the inspector that validates one.
 *
 * Frontends: C (.c .h .cpp .hpp: struct / union layout for lp64 or wasm32,
 * typedefs, function prototypes), COBOL (.cbl .cob .cpy: PIC, COMP, COMP-3,
 * OCCURS, REDEFINES), SQLite (.db .sqlite .sqlite3 .sql, see pw_sqlite.h),
 * assembly (.s .asm: basic blocks, CFG, cyclomatic complexity, stack frame),
 * ELF32/64 (.elf .o .so or ELF magic: header, sections, .symtab / .dynsym,
 * x86-64 CFG from the repo's decoder) and Rust (crate directory, .rs or
 * .rblob, through rblob functors).
 *
 * IR values are JSON objects with the field order of the original
 * dataclasses (RecordIR, FieldLayout, FunctionCFG, BasicBlockIR, SymbolIR).
 * C23. */
#ifndef PW_BSM_H
#define PW_BSM_H

#include <stddef.h>
#include <stdint.h>

#include "pw_json.h"

typedef struct {
    pj *sources, *records, *cfgs, *symbols, *elf_headers, *cross_links, *functors;
} pw_holo_ir;

void pw_holo_ir_init(pw_holo_ir *ir);
void pw_holo_ir_free(pw_holo_ir *ir);

void pw_bsm_parse_c(const char *text, size_t len, const char *fname, const char *abi, pj *records, pj *symbols);
void pw_bsm_parse_cobol(const char *text, size_t len, const char *fname, pj *records, pj *symbols);
void pw_bsm_parse_asm(const char *text, size_t len, const char *fname, const char *source_kind, pj *cfgs, pj *symbols);
/* Returns the header dict; appends symbols and CFGs. Exits on a non-ELF. */
[[nodiscard]] pj *pw_bsm_parse_elf(const char *path, const char *fname, pj *symbols, pj *cfgs);
void pw_bsm_analyze(pw_holo_ir *ir);

/* ingest_paths(): every input in order, then cross-source linking. */
void pw_bsm_ingest(pw_holo_ir *ir, const char *const *paths, size_t n, const char *abi);

/* pack_wasm_holo(): module bytes and the manifest dict. */
[[nodiscard]] uint8_t *pw_bsm_pack(const pw_holo_ir *ir, size_t *len, pj **manifest);
/* inspect_wasm_holo(): the report dict, or nullptr with an error message. */
[[nodiscard]] pj *pw_bsm_inspect(const uint8_t *wasm, size_t len, char *err, size_t errcap);

#endif /* PW_BSM_H */
