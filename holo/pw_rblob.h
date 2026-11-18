/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Rust crate ingestor: Cargo.toml + src/ (every *.rs, sorted) or one .rs
 * file -> crate IR (structs with repr / field ABI layout, functions with
 * impl owner and trait, traits, macro_rules!) -> .rblob:
 *   [0..6)   "RBLB" 01 00
 *   [6..38)  SHA-256 of the payload
 *   [38..42) payload length, uint32 little-endian
 *   [42..)   payload: the crate IR as canonical JSON (sorted keys, compact)
 * and the verified blob -> categorical functors (object map f_obj, morphism
 * map f_mor, functor laws, Lean 4 signature). C23. */
#ifndef PW_RBLOB_H
#define PW_RBLOB_H

#include <stddef.h>
#include <stdint.h>

#include "pw_json.h"

#define PW_RBLOB_MAGIC "RBLB\x01\x00"
#define PW_RBLOB_HEADER 42u

/* Crate IR: {crate, version, files, structs, functions, traits, macros}.
 * Exits with a message when a source file cannot be read. */
[[nodiscard]] pj *pw_rblob_parse_crate(const char *crate_path);
/* Blob bytes (malloc'd) and the payload digest as hex. */
[[nodiscard]] uint8_t *pw_rblob_build(const pj *crate_ir, size_t *len, char hex[65]);
/* {verified, sha256, blob_bytes, crate_ir}, or nullptr with the error text
 * ("ValueError: ...") in err. */
[[nodiscard]] pj *pw_rblob_verify(const uint8_t *blob, size_t len, char *err, size_t errcap);
/* {verified, sha256, crate, version, functor_count, functors}. */
[[nodiscard]] pj *pw_rblob_disassemble(const uint8_t *blob, size_t len, char *err, size_t errcap);

#endif /* PW_RBLOB_H */
