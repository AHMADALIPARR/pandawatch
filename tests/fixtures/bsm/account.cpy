      * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
      * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
       01  ACCOUNT-RECORD.
           05  ACCT-STATUS          PIC X(1).
           05  ACCT-ID              PIC 9(9) COMP.
           05  ACCT-BALANCE         PIC S9(11)V99 COMP-3.
           05  ACCT-CURRENCY        PIC X(3).
           05  ACCT-FLAGS-RAW       PIC X(4).
           05  ACCT-FLAGS-NUM       REDEFINES ACCT-FLAGS-RAW
                                    PIC 9(4) COMP.
           05  ACCT-HISTORY         PIC S9(7)V99 COMP-3 OCCURS 4.
