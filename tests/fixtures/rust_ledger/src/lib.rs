pub trait Settlement {
    fn settle(&mut self, delta: i64) -> i32;
}

#[repr(C)]
pub struct AccountRecord {
    pub status: u8,
    pub account_id: u32,
    pub balance_cents: i64,
}

impl AccountRecord {
    pub fn new(id: u32, bal: i64) -> AccountRecord {
        AccountRecord { status: 1, account_id: id, balance_cents: bal }
    }
}

impl Settlement for AccountRecord {
    fn settle(&mut self, delta: i64) -> i32 {
        self.balance_cents += delta;
        0
    }
}

pub fn process_tx(acc: &mut AccountRecord, delta: i32) -> i32 {
    acc.settle(delta as i64)
}
