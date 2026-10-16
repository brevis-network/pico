use coprocessor_sdk::{
    data_types::{address::Address, byte32::Bytes32},
    input_types::receipt::{LogFieldData, ReceiptData},
    Hex,
};
use crypto_bigint::U256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TradingVolumnReceipts {
    pub receipts: Vec<ReceiptData>,
    pub expect_event_swap: Bytes32,
    pub expect_event_transfer: Bytes32,
    pub expect_usdc_pool: Address,
    pub expect_user_addr: U256,
    pub max_receipts: usize,
}
// update this to change the workload of trading volumn receipts
const MAX_RECEIPT: usize = 64;

pub fn prepare_test_receipts() -> TradingVolumnReceipts {
    let transaction_hash: &str =
        "0xd97c7863076f6b8a2430f3cc363220a1d67ee990d2673c927c93822fa541d39c";
    let transaction_hash = Bytes32::from_hex(transaction_hash).unwrap();

    let block_num = 21756846;

    let usdc_pool_hex = "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640";
    let usdc_pool: [u8; 20] = Address::from_hex(&usdc_pool_hex).unwrap();

    let event_swap: &str = "0xc42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67";
    let event_swap = Bytes32::from_hex(event_swap).unwrap();

    let event_transfer: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    let event_transfer = Bytes32::from_hex(event_transfer).unwrap();

    let user_addr_hex = "0000000000000000000000006a000f20005980200259b80c5102003040001068";

    let field_0 = LogFieldData {
        log_pos: 17,
        field_index: 1,
        is_topic: false,
        contract: usdc_pool,
        topic: event_swap,
        value: U256::from_be_hex(
            "0000000000000000000000000000000000000000000000010d12bdb167e201e0",
        ),
    };

    let field_1 = LogFieldData {
        contract: usdc_pool,
        topic: event_swap,
        log_pos: 17,
        field_index: 2,
        is_topic: true,
        value: U256::from_be_hex(
            "0000000000000000000000006a000f20005980200259b80c5102003040001068",
        ),
    };

    let mut test_fields = Vec::with_capacity(4);
    test_fields.push(field_0.clone());
    test_fields.push(field_1.clone());
    test_fields.push(field_1.clone());
    test_fields.push(field_1.clone());

    let mpt_key_path = 1; // 0x01;
    let block_time = 1738475315;
    let base_fee = U256::from_u64(1494611587);

    let mut test_receipts = Vec::with_capacity(64);
    let test_receipt = ReceiptData::add_receipt(
        transaction_hash,
        block_num,
        base_fee,
        block_time,
        mpt_key_path,
        test_fields,
    );
    (0..MAX_RECEIPT).for_each(|_| {
        test_receipts.push(test_receipt.clone());
    });

    TradingVolumnReceipts {
        receipts: test_receipts,
        expect_event_swap: event_swap,
        expect_event_transfer: event_transfer,
        expect_usdc_pool: usdc_pool,
        expect_user_addr: U256::from_be_hex(&user_addr_hex),
        max_receipts: MAX_RECEIPT,
    }
}
