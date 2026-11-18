/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
/* C prototypes for the FORTRAN 77 struct parser in fortran/pw_struct.f.
 * gfortran externals: lower-case name plus '_', every argument by reference,
 * CHARACTER*(*) adds a trailing hidden size_t length. */
#ifndef PW_FORTRAN_H
#define PW_FORTRAN_H

#include <stddef.h>
#include <stdint.h>

/* KIND values accepted by the Fortran routines. */
enum : int32_t {
    PWF_OPERAND = 1,   /* pw_operand_t, 16 bytes */
    PWF_INST = 2,      /* pw_ir_inst_t, 64 bytes */
    PWF_BLOCK = 3,     /* pw_ir_block_t, 32 bytes */
    PWF_FUNC_HDR = 4,  /* pw_ir_func_hdr_t, 64 bytes */
    PWF_RECORD = 5,    /* pw_evidence_record_t, 64 bytes */
    PWF_MANIFEST = 6,  /* pw_evidence_manifest_t, 192 bytes */
};

/* Largest number of decoded values for any kind (manifest: 9 scalars + 5 digests * 4). */
constexpr int32_t PWF_MAX_VALS = 29;

void pwlayt_(const int32_t *kind, const int32_t *i, int32_t *ioff, int32_t *isiz,
             int32_t *ipad, int32_t *ierr);
void pwfnam_(const int32_t *kind, const int32_t *i, char *name, size_t name_len);
int64_t pwgetn_(const uint8_t *b, const int32_t *ioff, const int32_t *n);
void pwputn_(uint8_t *b, const int32_t *ioff, const int32_t *n, const int64_t *v);
void pwdec_(const int32_t *kind, const uint8_t *b, const int32_t *nb, int64_t *vals,
            int32_t *nv, int32_t *ierr);
void pwenc_(const int32_t *kind, const int64_t *vals, uint8_t *b, const int32_t *nb,
            int32_t *ierr);
void pwval_(const int32_t *kind, const uint8_t *b, const int32_t *nb, int32_t *ibad,
            int32_t *ierr);
int64_t pwadl_(const uint8_t *b, const int32_t *n);
void pwrst_(const uint8_t *b, const int32_t *nrec, int32_t istat[11], double dstat[9]);

#endif /* PW_FORTRAN_H */
