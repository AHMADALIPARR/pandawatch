/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Prototypes for the canonical serializers in src/pw_xray_canon_checked.c
 * (the function bodies come unchanged from the spec's pw_xray_canon.c). */
#ifndef PW_XRAY_CANON_H
#define PW_XRAY_CANON_H

#include <stdint.h>
#include "pw_xray_ir.h"
#include "pw_xray_evidence_checked.h"

void pw_serialize_ir_inst(const pw_ir_inst_t *in, uint8_t out[64]);
void pw_serialize_evidence_record(const pw_evidence_record_t *rec, uint8_t out[64]);

#endif /* PW_XRAY_CANON_H */
