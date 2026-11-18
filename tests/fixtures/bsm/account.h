/* SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
 * Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
 */
#ifndef BSM_ACCOUNT_H
#define BSM_ACCOUNT_H
#include <stdint.h>

typedef uint64_t ledger_amount_t;

typedef struct AccountRecord {
    uint8_t status;
    uint32_t account_id;
    int64_t balance_cents;
    char currency[4];
} AccountRecord;

union parts {
    uint64_t raw_bits;
    struct { uint32_t amount; uint16_t flags; } split;
};

struct Transaction {
    uint32_t tx_id;
    uint32_t account_id;
    ledger_amount_t amount;
    double rate;
    char *memo;
};

int post_transaction(AccountRecord *acct, const struct Transaction *tx);
int64_t account_balance(const AccountRecord *acct);
#endif
