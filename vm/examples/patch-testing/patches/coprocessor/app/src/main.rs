//! Guest exercise for `pico-sdk`'s `coprocessor` feature.
//!
//! This is the trading-volume example of `brevis-network/Pico-zkCoprocessor`: its `app` is this
//! file and its `lib` is `receipts.rs`, both as they are there except for the `mod` line, the one
//! `use` that now names it, and this repository's import formatting. It checks 64 copies of one
//! swap receipt field by field and sums their volume. The built ELF ships as
//! `perf/bench_data/rv64/coprocessor-elf`, which `--elf coprocessor` in
//! `vm/examples/common/parse_args.rs` runs.
//!
//! What it covers is the part of the SDK only this feature reaches:
//!
//! - `Builder::init` commits the receipts as a Poseidon2 Merkle root computed through
//!   `syscall_poseidon2_permute` -- 638 permutations, each of which the precompile's alignment and
//!   canonicality checks have to accept;
//! - `commit_coprocessor_bytes` writes that root and the three dummy commitments to the public
//!   values, and the volume to the coprocessor output stream (fd 9);
//! - `syscall_halt` folds that stream's digest into the public values.

#![no_main]

mod receipts;

use coprocessor_sdk::sdk::Builder;
use crypto_bigint::{Zero, U256};
use receipts::prepare_test_receipts;

pico_sdk::entrypoint!(main);
pub fn main() {
    let test_receipts = prepare_test_receipts();

    let mut volume = U256::zero();
    let mut sdk: coprocessor_sdk::sdk::SDK = Builder::new()
        .with_receipts(test_receipts.receipts)
        .init(test_receipts.max_receipts as u32, 0, 0);

    if let Some(receipts) = sdk.receipts.clone() {
        for receipt in receipts {
            if !(receipt.fields[0].log_pos == receipt.fields[1].log_pos) {
                panic!("log field log pos mismatches");
            }

            let receipt_user_addr = receipt.fields[1].value;

            if test_receipts.expect_user_addr != receipt_user_addr {
                panic!("user address mismatches");
            }
            if receipt.fields[0].contract != test_receipts.expect_usdc_pool {
                panic!("usdc pool address mismatches");
            }

            if receipt.fields[0].topic != test_receipts.expect_event_swap {
                panic!("swap event topic mismatches");
            }

            if receipt.fields[1].topic != test_receipts.expect_event_swap {
                panic!("transfer event topic mismatches");
            }

            volume += receipt.fields[0].value;
        }
    }
    pico_sdk::io::commit_coprocessor_bytes(&mut sdk, &mut volume.to_be_bytes());
}
