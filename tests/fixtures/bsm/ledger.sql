-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SnapKitty-Opaque-1.0
-- Copyright (C) 2026 Ahmad Ali Parr / SnapKitty Research Lab
CREATE TABLE account_record (
    account_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL,
    balance_cents INTEGER NOT NULL DEFAULT 0,
    currency TEXT NOT NULL
);
CREATE TABLE transactions (
    tx_id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES account_record(account_id),
    amount_cents INTEGER NOT NULL,
    rate REAL,
    memo TEXT,
    UNIQUE (account_id, tx_id)
);
CREATE INDEX idx_tx_account ON transactions(account_id);
INSERT INTO account_record VALUES (1, 'A', 125000, 'USD');
INSERT INTO account_record VALUES (2, 'A', 98000, 'EUR');
INSERT INTO transactions VALUES (10, 1, -2500, 1.0, 'coffee');
INSERT INTO transactions VALUES (11, 2, 4000, 1.08, 'refund');
