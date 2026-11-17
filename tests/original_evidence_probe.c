/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* Compiled by ctest with -fsyntax-only -Werror. pw_xray_evidence.h (with the
 * uint64_t _reserved1 fix) must compile as-is: the manifest is 192 bytes and
 * manifest_sha256 sits at offset 160, so the seal covers bytes [0, 160). */
#include "pw_xray_evidence.h"

#include <stddef.h>

_Static_assert(sizeof(pw_evidence_manifest_t) == 192, "manifest is 192 bytes");
_Static_assert(offsetof(pw_evidence_manifest_t, _reserved1) == 152, "_reserved1 at 152");
_Static_assert(offsetof(pw_evidence_manifest_t, manifest_sha256) == 160, "manifest_sha256 at 160");
_Static_assert(sizeof(pw_evidence_record_t) == 64, "record is 64 bytes");
