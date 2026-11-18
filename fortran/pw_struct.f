C SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
C Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
C
C PANDAWATCH X-RAY C struct parser in FORTRAN 77 (fixed form).
C
C Decodes and encodes the little-endian wire layout of the C structs
C in include/pandawatch/pw_xray_ir.h and pw_xray_evidence.h, checks
C their padding, and computes checksums and statistics over records.
C
C Calling convention (gfortran, no ISO_C_BINDING): every routine is a
C plain external. From C the name is lower case with a trailing
C underscore and every argument is passed by reference:
C   INTEGER          -> int32_t *
C   INTEGER*8        -> int64_t *
C   INTEGER*1 B(*)   -> uint8_t * (bytes; values >127 read as negative)
C   DOUBLE PRECISION -> double *
C   CHARACTER*(*)    -> char *, plus a hidden size_t length appended
C                       after all other arguments
C INTEGER*8 functions return int64_t.
C
C Struct kinds (KIND):
C   1 pw_operand_t (16)          2 pw_ir_inst_t (64)
C   3 pw_ir_block_t (32)         4 pw_ir_func_hdr_t (64)
C   5 pw_evidence_record_t (64)  6 pw_evidence_manifest_t (192)
C
C Error codes (IERR): 0 ok, 1 bad kind, 2 buffer too short,
C 3 bad field index.

C ----------------------------------------------------------------
C PWLAYT: layout table. Field I (1-based) of struct KIND:
C byte offset IOFF, size ISIZ (1, 2, 4, 8 or 32) and IPAD = 1 if the
C field is padding or reserved and must be zero.
C ----------------------------------------------------------------
      SUBROUTINE PWLAYT(KIND, I, IOFF, ISIZ, IPAD, IERR)
      INTEGER KIND, I, IOFF, ISIZ, IPAD, IERR
      INTEGER NTOT
      PARAMETER (NTOT = 63)
      INTEGER KFIRST(6), KCOUNT(6), KSIZE(6)
      INTEGER FOFF(NTOT), FSIZ(NTOT), FPAD(NTOT)
      INTEGER K
      SAVE KFIRST, KCOUNT, KSIZE, FOFF, FSIZ, FPAD
      DATA KFIRST /  1,  6, 26, 33, 40, 50 /
      DATA KCOUNT /  5, 20,  7,  7, 10, 14 /
      DATA KSIZE  / 16, 64, 32, 64, 64, 192 /
C     pw_operand_t: kind type _pad0 ref_id imm_val
      DATA (FOFF(K), K = 1, 5)   / 0, 1, 2, 4, 8 /
      DATA (FSIZ(K), K = 1, 5)   / 1, 1, 2, 4, 8 /
      DATA (FPAD(K), K = 1, 5)   / 0, 0, 1, 0, 0 /
C     pw_ir_inst_t: ssa_id opcode out_type flags source_va src[3]
      DATA (FOFF(K), K = 6, 25)  / 0, 4, 6, 7, 8,
     &  16, 17, 18, 20, 24,  32, 33, 34, 36, 40,  48, 49, 50, 52, 56 /
      DATA (FSIZ(K), K = 6, 25)  / 4, 2, 1, 1, 8,
     &   1,  1,  2,  4,  8,   1,  1,  2,  4,  8,   1,  1,  2,  4,  8 /
      DATA (FPAD(K), K = 6, 25)  / 0, 0, 0, 0, 0,
     &   0,  0,  1,  0,  0,   0,  0,  1,  0,  0,   0,  0,  1,  0,  0 /
C     pw_ir_block_t
      DATA (FOFF(K), K = 26, 32) / 0, 4, 8, 12, 16, 20, 24 /
      DATA (FSIZ(K), K = 26, 32) / 4, 4, 4,  4,  4,  4,  8 /
      DATA (FPAD(K), K = 26, 32) / 0, 0, 0,  0,  0,  0,  0 /
C     pw_ir_func_hdr_t
      DATA (FOFF(K), K = 33, 39) / 0, 4, 8, 12, 16, 24, 56 /
      DATA (FSIZ(K), K = 33, 39) / 4, 4, 4,  4,  8, 32,  8 /
      DATA (FPAD(K), K = 33, 39) / 0, 0, 0,  0,  0,  0,  1 /
C     pw_evidence_record_t
      DATA (FOFF(K), K = 40, 49) / 0, 4, 5, 6, 8, 10, 12, 16, 24, 56 /
      DATA (FSIZ(K), K = 40, 49) / 4, 1, 1, 2, 2,  2,  4,  8, 32,  8 /
      DATA (FPAD(K), K = 40, 49) / 0, 0, 1, 0, 0,  0,  0,  0,  0,  1 /
C     pw_evidence_manifest_t
      DATA (FOFF(K), K = 50, 63) / 0, 4, 8, 9, 10, 11, 12, 16,
     &  24, 56, 88, 120, 152, 160 /
      DATA (FSIZ(K), K = 50, 63) / 4, 4, 1, 1, 1, 1, 4, 8,
     &  32, 32, 32, 32, 8, 32 /
      DATA (FPAD(K), K = 50, 63) / 0, 0, 0, 0, 0, 1, 0, 0,
     &   0,  0,  0,  0, 1,  0 /
      IERR = 0
      IOFF = 0
      ISIZ = 0
      IPAD = 0
      IF (KIND .LT. 1 .OR. KIND .GT. 6) THEN
         IERR = 1
         RETURN
      ENDIF
      IF (I .EQ. 0) THEN
C        I = 0 returns the struct size in ISIZ and field count in IOFF
         IOFF = KCOUNT(KIND)
         ISIZ = KSIZE(KIND)
         RETURN
      ENDIF
      IF (I .LT. 1 .OR. I .GT. KCOUNT(KIND)) THEN
         IERR = 3
         RETURN
      ENDIF
      K = KFIRST(KIND) + I - 1
      IOFF = FOFF(K)
      ISIZ = FSIZ(K)
      IPAD = FPAD(K)
      RETURN
      END

C ----------------------------------------------------------------
C PWFNAM: C field name of field I of struct KIND (blank if invalid).
C ----------------------------------------------------------------
      SUBROUTINE PWFNAM(KIND, I, NAME)
      INTEGER KIND, I
      CHARACTER*(*) NAME
      CHARACTER*20 FN(63)
      INTEGER KFIRST(6), KCOUNT(6)
      INTEGER K
      SAVE FN, KFIRST, KCOUNT
      DATA KFIRST / 1, 6, 26, 33, 40, 50 /
      DATA KCOUNT / 5, 20, 7, 7, 10, 14 /
      DATA (FN(K), K = 1, 5) / 'kind', 'type', '_pad0', 'ref_id',
     &  'imm_val' /
      DATA (FN(K), K = 6, 25) / 'ssa_id', 'opcode', 'out_type',
     &  'flags', 'source_va',
     &  'src0.kind', 'src0.type', 'src0._pad0', 'src0.ref_id',
     &  'src0.imm_val',
     &  'src1.kind', 'src1.type', 'src1._pad0', 'src1.ref_id',
     &  'src1.imm_val',
     &  'src2.kind', 'src2.type', 'src2._pad0', 'src2.ref_id',
     &  'src2.imm_val' /
      DATA (FN(K), K = 26, 32) / 'block_id', 'first_inst',
     &  'inst_count', 'succ_count', 'succ_blocks0', 'succ_blocks1',
     &  'start_va' /
      DATA (FN(K), K = 33, 39) / 'func_id', 'block_count',
     &  'inst_count', 'stack_frame_bytes', 'entry_va', 'ir_sha256',
     &  '_reserved' /
      DATA (FN(K), K = 40, 49) / 'record_id', 'verdict', '_pad0',
     &  'rule_id', 'unknown_reason', 'detected_bytes',
     &  'required_bytes', 'site_va', 'func_ir_sha256', '_reserved' /
      DATA (FN(K), K = 50, 63) / 'magic', 'version',
     &  'container_format', 'arch', 'overall_verdict', '_pad0',
     &  'record_count', 'binary_size_bytes', 'binary_sha256',
     &  'ir_corpus_sha256', 'alloy_model_sha256', 'records_sha256',
     &  '_reserved1', 'manifest_sha256' /
      NAME = ' '
      IF (KIND .LT. 1 .OR. KIND .GT. 6) RETURN
      IF (I .LT. 1 .OR. I .GT. KCOUNT(KIND)) RETURN
      NAME = FN(KFIRST(KIND) + I - 1)
      RETURN
      END

C ----------------------------------------------------------------
C PWGETN: unsigned little-endian integer of N bytes (1..8) at 0-based
C byte offset IOFF of B. 8-byte values come back as the same 64 bits.
C ----------------------------------------------------------------
      INTEGER*8 FUNCTION PWGETN(B, IOFF, N)
      INTEGER*1 B(*)
      INTEGER IOFF, N
      INTEGER*8 V, T, MASK
      INTEGER K
      MASK = 255
      V = 0
      DO 10 K = N - 1, 0, -1
         T = B(IOFF + K + 1)
         V = IOR(ISHFT(V, 8), IAND(T, MASK))
   10 CONTINUE
      PWGETN = V
      RETURN
      END

C ----------------------------------------------------------------
C PWPUTN: store the low N bytes of V little-endian at offset IOFF.
C Each byte is mapped to -128..127 first, so the store into INTEGER*1
C is exact.
C ----------------------------------------------------------------
      SUBROUTINE PWPUTN(B, IOFF, N, V)
      INTEGER*1 B(*)
      INTEGER IOFF, N
      INTEGER*8 V, T, MASK
      INTEGER K
      MASK = 255
      DO 10 K = 0, N - 1
         T = IAND(ISHFT(V, -8 * K), MASK)
         IF (T .GT. 127) T = T - 256
         B(IOFF + K + 1) = T
   10 CONTINUE
      RETURN
      END

C ----------------------------------------------------------------
C PWDEC: decode struct KIND from bytes B(1..NB) into VALS(1..NV).
C Each 1/2/4/8-byte field gives one value; each 32-byte digest gives
C four 64-bit little-endian lanes.
C ----------------------------------------------------------------
      SUBROUTINE PWDEC(KIND, B, NB, VALS, NV, IERR)
      INTEGER KIND, NB, NV, IERR
      INTEGER*1 B(*)
      INTEGER*8 VALS(*)
      INTEGER*8 PWGETN
      EXTERNAL PWGETN
      INTEGER NF, KSIZ, I, J, IOFF, ISIZ, IPAD
      NV = 0
      CALL PWLAYT(KIND, 0, NF, KSIZ, IPAD, IERR)
      IF (IERR .NE. 0) RETURN
      IF (NB .LT. KSIZ) THEN
         IERR = 2
         RETURN
      ENDIF
      DO 10 I = 1, NF
         CALL PWLAYT(KIND, I, IOFF, ISIZ, IPAD, IERR)
         IF (ISIZ .EQ. 32) THEN
            DO 20 J = 0, 3
               NV = NV + 1
               VALS(NV) = PWGETN(B, IOFF + 8 * J, 8)
   20       CONTINUE
         ELSE
            NV = NV + 1
            VALS(NV) = PWGETN(B, IOFF, ISIZ)
         ENDIF
   10 CONTINUE
      RETURN
      END

C ----------------------------------------------------------------
C PWENC: encode VALS (same order as PWDEC) into bytes B of struct KIND.
C Padding and reserved fields are always written as zero.
C ----------------------------------------------------------------
      SUBROUTINE PWENC(KIND, VALS, B, NB, IERR)
      INTEGER KIND, NB, IERR
      INTEGER*8 VALS(*)
      INTEGER*1 B(*)
      INTEGER*8 ZERO
      INTEGER NF, KSIZ, I, J, IOFF, ISIZ, IPAD, NV
      ZERO = 0
      CALL PWLAYT(KIND, 0, NF, KSIZ, IPAD, IERR)
      IF (IERR .NE. 0) RETURN
      IF (NB .LT. KSIZ) THEN
         IERR = 2
         RETURN
      ENDIF
      NV = 0
      DO 10 I = 1, NF
         CALL PWLAYT(KIND, I, IOFF, ISIZ, IPAD, IERR)
         IF (ISIZ .EQ. 32) THEN
            DO 20 J = 0, 3
               NV = NV + 1
               CALL PWPUTN(B, IOFF + 8 * J, 8, VALS(NV))
   20       CONTINUE
         ELSE
            NV = NV + 1
            IF (IPAD .EQ. 1) THEN
               CALL PWPUTN(B, IOFF, ISIZ, ZERO)
            ELSE
               CALL PWPUTN(B, IOFF, ISIZ, VALS(NV))
            ENDIF
         ENDIF
   10 CONTINUE
      RETURN
      END

C ----------------------------------------------------------------
C PWVAL: IBAD = index of the first padding/reserved field of struct
C KIND in B that is not zero, or 0 if all padding is zero.
C ----------------------------------------------------------------
      SUBROUTINE PWVAL(KIND, B, NB, IBAD, IERR)
      INTEGER KIND, NB, IBAD, IERR
      INTEGER*1 B(*)
      INTEGER*8 PWGETN
      EXTERNAL PWGETN
      INTEGER NF, KSIZ, I, IOFF, ISIZ, IPAD
      IBAD = 0
      CALL PWLAYT(KIND, 0, NF, KSIZ, IPAD, IERR)
      IF (IERR .NE. 0) RETURN
      IF (NB .LT. KSIZ) THEN
         IERR = 2
         RETURN
      ENDIF
      DO 10 I = 1, NF
         CALL PWLAYT(KIND, I, IOFF, ISIZ, IPAD, IERR)
         IF (IPAD .EQ. 1) THEN
            IF (PWGETN(B, IOFF, ISIZ) .NE. 0) THEN
               IBAD = I
               RETURN
            ENDIF
         ENDIF
   10 CONTINUE
      RETURN
      END

C ----------------------------------------------------------------
C PWADL: Adler-32 checksum of bytes B(1..N).
C ----------------------------------------------------------------
      INTEGER*8 FUNCTION PWADL(B, N)
      INTEGER*1 B(*)
      INTEGER N
      INTEGER*8 A, S, T, MASK, MODA
      INTEGER I
      MASK = 255
      MODA = 65521
      A = 1
      S = 0
      DO 10 I = 1, N
         T = B(I)
         A = MOD(A + IAND(T, MASK), MODA)
         S = MOD(S + A, MODA)
   10 CONTINUE
      PWADL = S * 65536 + A
      RETURN
      END

C ----------------------------------------------------------------
C PWRST: statistics over NREC packed pw_evidence_record_t (64 bytes
C each) in B.
C   ISTAT(1..3)  records per verdict (COMPLIANT, VULNERABLE, UNKNOWN)
C   ISTAT(4..8)  records per unknown_reason 1..5
C   ISTAT(9)     records with required_bytes > detected_bytes
C   ISTAT(10)    records with an out-of-range verdict
C   ISTAT(11)    records with nonzero padding
C   DSTAT(1..4)  detected_bytes mean, variance, min, max
C   DSTAT(5..8)  required_bytes mean, variance, min, max
C   DSTAT(9)     total shortfall: sum of (required - detected) > 0
C Mean and population variance use Welford's update.
C ----------------------------------------------------------------
      SUBROUTINE PWRST(B, NREC, ISTAT, DSTAT)
      INTEGER*1 B(*)
      INTEGER NREC
      INTEGER ISTAT(11)
      DOUBLE PRECISION DSTAT(9)
      INTEGER*8 PWGETN
      EXTERNAL PWGETN
      INTEGER I, K, IOFF, IV, IR, IBAD, IERR
      DOUBLE PRECISION XD, XR, DM, DQ, RM, RQ, DD, DR, XN
      DO 5 K = 1, 11
         ISTAT(K) = 0
    5 CONTINUE
      DO 6 K = 1, 9
         DSTAT(K) = 0.0D0
    6 CONTINUE
      IF (NREC .LE. 0) RETURN
      DM = 0.0D0
      DQ = 0.0D0
      RM = 0.0D0
      RQ = 0.0D0
      DO 10 I = 1, NREC
         IOFF = (I - 1) * 64
         IV = INT(PWGETN(B, IOFF + 4, 1))
         IF (IV .GE. 1 .AND. IV .LE. 3) THEN
            ISTAT(IV) = ISTAT(IV) + 1
         ELSE
            ISTAT(10) = ISTAT(10) + 1
         ENDIF
         IR = INT(PWGETN(B, IOFF + 8, 2))
         IF (IR .GE. 1 .AND. IR .LE. 5) THEN
            ISTAT(3 + IR) = ISTAT(3 + IR) + 1
         ENDIF
         CALL PWVAL(5, B(IOFF + 1), 64, IBAD, IERR)
         IF (IBAD .NE. 0) ISTAT(11) = ISTAT(11) + 1
         XD = DBLE(PWGETN(B, IOFF + 10, 2))
         XR = DBLE(PWGETN(B, IOFF + 12, 4))
         IF (XR .GT. XD) THEN
            ISTAT(9) = ISTAT(9) + 1
            DSTAT(9) = DSTAT(9) + (XR - XD)
         ENDIF
         IF (I .EQ. 1) THEN
            DSTAT(3) = XD
            DSTAT(4) = XD
            DSTAT(7) = XR
            DSTAT(8) = XR
         ELSE
            DSTAT(3) = MIN(DSTAT(3), XD)
            DSTAT(4) = MAX(DSTAT(4), XD)
            DSTAT(7) = MIN(DSTAT(7), XR)
            DSTAT(8) = MAX(DSTAT(8), XR)
         ENDIF
         XN = DBLE(I)
         DD = XD - DM
         DM = DM + DD / XN
         DQ = DQ + DD * (XD - DM)
         DR = XR - RM
         RM = RM + DR / XN
         RQ = RQ + DR * (XR - RM)
   10 CONTINUE
      DSTAT(1) = DM
      DSTAT(2) = DQ / DBLE(NREC)
      DSTAT(5) = RM
      DSTAT(6) = RQ / DBLE(NREC)
      RETURN
      END
