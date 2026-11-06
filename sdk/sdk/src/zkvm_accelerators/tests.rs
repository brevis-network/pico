//! Host tests. A few known answers per function live here; `vectors` runs the full set that
//! zkevm-test-monitor's `gen_accel_vectors.py` produces, from JSON in `$PICO_ACCEL_VECTORS`.

use std::{collections::BTreeMap, path::PathBuf};

use serde_json::Value;

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn unhex_array<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap()
}

/// `zkvm_keccak256` and the others, on a byte string.
fn hash(
    f: unsafe extern "C" fn(*const u8, usize, *mut [u8; 32]) -> ZkvmStatus,
    data: &[u8],
) -> [u8; 32] {
    let mut out = [0xcc; 32];
    assert_eq!(unsafe { f(data.as_ptr(), data.len(), &mut out) }, ZKVM_EOK);
    out
}

#[test]
fn hashes() {
    let k = |d: &[u8]| hex::encode(hash(zkvm_keccak256, d));
    assert_eq!(
        k(b""),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
    assert_eq!(
        k(b"abc"),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
    let s = |d: &[u8]| hex::encode(hash(zkvm_sha256, d));
    assert_eq!(
        s(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        s(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let r = |d: &[u8]| hex::encode(hash(zkvm_ripemd160, d));
    assert_eq!(
        r(b"abc"),
        "0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
    );
}

/// Every length across the block boundaries, from every start address within a word.
#[test]
fn hashes_any_length_and_alignment() {
    use sha2::Digest as _;
    let buf: Vec<u8> = (0..400u32).map(|i| (i * 7 + 3) as u8).collect();
    for start in 0..8 {
        for len in
            (0..=300).filter(|l| l % 17 < 3 || (130..=140).contains(l) || (54..=66).contains(l))
        {
            let data = &buf[start..start + len];
            assert_eq!(
                hash(zkvm_sha256, data),
                <[u8; 32]>::from(sha2::Sha256::digest(data))
            );
            let mut want = [0u8; 32];
            let mut state = [0u64; 25];
            // Keccak-256 by the book, on the host's permutation.
            let mut padded = data.to_vec();
            padded.push(0x01);
            while !padded.len().is_multiple_of(136) {
                padded.push(0);
            }
            *padded.last_mut().unwrap() ^= 0x80;
            for block in padded.chunks(136) {
                for (lane, b) in state.iter_mut().zip(block.chunks(8)) {
                    *lane ^= u64::from_le_bytes(b.try_into().unwrap());
                }
                keccak::f1600(&mut state);
            }
            for (w, lane) in want.chunks_mut(8).zip(state) {
                w.copy_from_slice(&lane.to_le_bytes());
            }
            assert_eq!(
                hash(zkvm_keccak256, data),
                want,
                "keccak len {len} start {start}"
            );
        }
    }
}

#[test]
fn null_with_zero_length_is_empty() {
    let mut out = [0u8; 32];
    assert_eq!(
        unsafe { zkvm_sha256(core::ptr::null(), 0, &mut out) },
        ZKVM_EOK
    );
    assert_eq!(out, hash(zkvm_sha256, b""));
    // A zero modulus length writes nothing, so the output may be NULL too.
    let null = core::ptr::null();
    let status = unsafe { zkvm_modexp(null, 0, null, 0, null, 0, core::ptr::null_mut()) };
    assert_eq!(status, ZKVM_EOK);
    let mut verified = false;
    assert_eq!(
        unsafe { zkvm_bn254_pairing(core::ptr::null(), 0, &mut verified) },
        ZKVM_EOK
    );
    assert!(verified);
}

/// A NULL argument aborts the run. The functions cannot unwind, so each call runs in a child
/// process: this test binary again, running only the ignored test named.
#[test]
fn null_pointers_abort() {
    for (test, message) in [
        ("null_data", "zkvm_sha256: `data` is NULL"),
        ("null_output", "zkvm_keccak256: `output` is NULL"),
        ("null_point_output", "zkvm_bn254_g1_add: `result` is NULL"),
    ] {
        let name = format!("zkvm_accelerators::tests::{test}");
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([&name, "--exact", "--ignored", "--nocapture"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&child.stderr);
        assert!(!child.status.success(), "{test} returned");
        assert!(stderr.contains(message), "{test}: {stderr}");
    }
}

#[test]
#[ignore = "run by null_pointers_abort"]
fn null_data() {
    let mut out = [0u8; 32];
    unsafe { zkvm_sha256(core::ptr::null(), 32, &mut out) };
}

#[test]
#[ignore = "run by null_pointers_abort"]
fn null_output() {
    unsafe { zkvm_keccak256(b"abc".as_ptr(), 3, core::ptr::null_mut()) };
}

#[test]
#[ignore = "run by null_pointers_abort"]
fn null_point_output() {
    let p = [0u8; 64];
    unsafe { zkvm_bn254_g1_add(&p, &p, core::ptr::null_mut()) };
}

#[test]
fn modexp() {
    let run = |b: &str, e: &str, m: &str| {
        let (b, e, m) = (unhex(b), unhex(e), unhex(m));
        let mut out = vec![0xcc; m.len()];
        let status = unsafe {
            zkvm_modexp(
                b.as_ptr(),
                b.len(),
                e.as_ptr(),
                e.len(),
                m.as_ptr(),
                m.len(),
                out.as_mut_ptr(),
            )
        };
        assert_eq!(status, ZKVM_EOK);
        hex::encode(out)
    };
    // EIP-198's example: 3^(p-1) mod p = 1, for secp256k1's p.
    let p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
    let p_1 = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e";
    assert_eq!(run("03", p_1, p), format!("{:064x}", 1));
    assert_eq!(run("", p_1, p), format!("{:064}", 0));
    assert_eq!(run("05", "", "0007"), "0001");
    assert_eq!(run("05", "02", "0000"), "0000");
}

#[test]
fn blake2f() {
    // EIP-152's test vector 5: BLAKE2b-512("abc") after 12 rounds.
    let mut state: [u8; 64] = unhex_array("48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b");
    let m: [u8; 128] = unhex_array(&format!("616263{}", "00".repeat(125)));
    let t: [u8; 16] = unhex_array(&format!("03{}", "00".repeat(15)));
    assert_eq!(unsafe { zkvm_blake2f(12, &mut state, &m, &t, 1) }, ZKVM_EOK);
    assert_eq!(hex::encode(state), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    let before = state;
    assert_eq!(
        unsafe { zkvm_blake2f(12, &mut state, &m, &t, 2) },
        ZKVM_EFAIL
    );
    assert_eq!(state, before);
}

/// An output may share its address with an input.
#[test]
fn in_place() {
    // sha256 over its own output buffer.
    let mut buf = *b"abc_____________________________";
    let p = buf.as_mut_ptr();
    assert_eq!(unsafe { zkvm_sha256(p, 3, p as *mut [u8; 32]) }, ZKVM_EOK);
    assert_eq!(buf, hash(zkvm_sha256, b"abc"));
    // G + G into G's own bytes.
    let mut g = unhex_array::<64>(&format!("{:064x}{:064x}", 1, 2));
    let mut two_g = [0u8; 64];
    let two = unhex_array::<32>(&format!("{:064x}", 2));
    assert_eq!(unsafe { zkvm_bn254_g1_mul(&g, &two, &mut two_g) }, ZKVM_EOK);
    let p: *mut [u8; 64] = &mut g;
    assert_eq!(unsafe { zkvm_bn254_g1_add(p, p, p) }, ZKVM_EOK);
    assert_eq!(g, two_g);
    // 3^2 mod 7 over the base.
    let mut base = [0u8, 3];
    let (e, m) = ([2u8], [0u8, 7]);
    let b = base.as_mut_ptr();
    assert_eq!(
        unsafe { zkvm_modexp(b, 2, e.as_ptr(), 1, m.as_ptr(), 2, b) },
        ZKVM_EOK
    );
    assert_eq!(base, [0, 2]);
}

/// An off-curve point fails before the subgroup check, which would run on it otherwise.
#[test]
fn bls12_off_curve_point_with_y_zero_fails() {
    let mut point = [0u8; 96];
    point[47] = 1; // (1, 0)
    let pair = Bls12G1MsmPair {
        point,
        scalar: [1; 32],
    };
    let mut out = [0u8; 96];
    assert_eq!(unsafe { zkvm_bls12_g1_msm(&pair, 1, &mut out) }, ZKVM_EFAIL);
}

/// The constant standing in for the crate's map at 0 is a point of G2.
#[test]
fn map_fp2_to_g2_zero_is_in_g2() {
    let p = super::bls12_381::MAP_FP2_TO_G2_ZERO;
    assert!(super::bls12_381::decode_g2(&p, true).is_some());
    let mut out = [0xcc; 192];
    assert_eq!(
        unsafe { zkvm_bls12_map_fp2_to_g2(&[0; 96], &mut out) },
        ZKVM_EOK
    );
    assert_eq!(out, p);
}

#[test]
fn bn254() {
    let g = unhex_array::<64>(&format!("{:064x}{:064x}", 1, 2));
    let mut out = [0xcc; 64];
    // G + G == 2 * G, and G + (-G) is the point at infinity.
    assert_eq!(unsafe { zkvm_bn254_g1_add(&g, &g, &mut out) }, ZKVM_EOK);
    let mut two_g = [0xcc; 64];
    let two = unhex_array::<32>(&format!("{:064x}", 2));
    assert_eq!(unsafe { zkvm_bn254_g1_mul(&g, &two, &mut two_g) }, ZKVM_EOK);
    assert_eq!(out, two_g);
    let neg_g = unhex_array::<64>(&format!(
        "{:064x}30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
        1
    ));
    assert_eq!(unsafe { zkvm_bn254_g1_add(&g, &neg_g, &mut out) }, ZKVM_EOK);
    assert_eq!(out, [0; 64]);
    // The scalar reduces mod r: r * G is the point at infinity.
    let r = unhex_array::<32>("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    assert_eq!(unsafe { zkvm_bn254_g1_mul(&g, &r, &mut out) }, ZKVM_EOK);
    assert_eq!(out, [0; 64]);
    // (1, 3) is not on the curve.
    let bad = unhex_array::<64>(&format!("{:064x}{:064x}", 1, 3));
    assert_eq!(unsafe { zkvm_bn254_g1_add(&g, &bad, &mut out) }, ZKVM_EFAIL);
}

/// The full vector set, when `$PICO_ACCEL_VECTORS` names a directory of `<function>.json`.
#[test]
fn vectors() {
    let Some(dir) = std::env::var_os("PICO_ACCEL_VECTORS").map(PathBuf::from) else {
        eprintln!("PICO_ACCEL_VECTORS not set; skipping the full vector set");
        return;
    };
    let mut failures = Vec::new();
    let mut counts = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let function = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let cases: Vec<Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for case in &cases {
            if let Err(e) = run_case(&function, case) {
                failures.push(format!(
                    "{function} [{}]: {e}",
                    case["label"].as_str().unwrap()
                ));
            }
        }
        counts.insert(function, cases.len());
    }
    eprintln!("{counts:?}");
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_case(function: &str, case: &Value) -> Result<(), String> {
    let b = |k: &str| unhex(case[k].as_str().unwrap_or_else(|| panic!("{k}")));
    let n = |k: &str| case[k].as_u64().unwrap();
    let expect = case["expect"].as_str().unwrap();
    let fixed = |k: &str| b(k);

    // (status, written output) or (status, verified).
    enum Got {
        Out(ZkvmStatus, Vec<u8>),
        Verdict(ZkvmStatus, bool),
    }
    macro_rules! out_fn {
        ($f:expr, $n:literal, $($a:expr),*) => {{
            let mut out = [0xccu8; $n];
            let s = unsafe { $f($($a,)* &mut out) };
            Got::Out(s, out.to_vec())
        }};
    }
    macro_rules! verdict_fn {
        ($f:expr, $($a:expr),*) => {{
            let mut v = false;
            let s = unsafe { $f($($a,)* &mut v) };
            Got::Verdict(s, v)
        }};
    }
    fn p<const N: usize>(v: &[u8]) -> [u8; N] {
        v.try_into().unwrap()
    }
    fn pairs<T>(v: &[u8]) -> (*const T, usize) {
        assert_eq!(v.len() % size_of::<T>(), 0);
        (v.as_ptr() as *const T, v.len() / size_of::<T>())
    }

    let got = match function {
        "zkvm_keccak256" | "zkvm_sha256" | "zkvm_ripemd160" => {
            let f = match function {
                "zkvm_keccak256" => zkvm_keccak256,
                "zkvm_sha256" => zkvm_sha256,
                _ => zkvm_ripemd160,
            };
            let d = b("data");
            out_fn!(f, 32, d.as_ptr(), d.len())
        }
        "zkvm_modexp" => {
            let (base, exp, m) = (b("base"), b("exp"), b("mod"));
            let mut out = vec![0xcc; m.len()];
            let s = unsafe {
                zkvm_modexp(
                    base.as_ptr(),
                    base.len(),
                    exp.as_ptr(),
                    exp.len(),
                    m.as_ptr(),
                    m.len(),
                    out.as_mut_ptr(),
                )
            };
            Got::Out(s, out)
        }
        "zkvm_blake2f" => {
            let mut hh: [u8; 64] = p(&b("h"));
            let s = unsafe {
                zkvm_blake2f(
                    n("rounds") as u32,
                    &mut hh,
                    &p(&b("m")),
                    &p(&b("t")),
                    n("f") as u8,
                )
            };
            Got::Out(s, hh.to_vec())
        }
        "zkvm_secp256k1_ecrecover" => {
            out_fn!(
                zkvm_secp256k1_ecrecover,
                64,
                &p(&b("msg")),
                &p(&b("sig")),
                n("recid") as u8
            )
        }
        "zkvm_secp256k1_verify" => {
            verdict_fn!(
                zkvm_secp256k1_verify,
                &p(&b("msg")),
                &p(&b("sig")),
                &p(&b("pubkey"))
            )
        }
        "zkvm_secp256r1_verify" => {
            verdict_fn!(
                zkvm_secp256r1_verify,
                &p(&b("msg")),
                &p(&b("sig")),
                &p(&b("pubkey"))
            )
        }
        "zkvm_bn254_g1_add" => out_fn!(zkvm_bn254_g1_add, 64, &p(&fixed("p1")), &p(&fixed("p2"))),
        "zkvm_bn254_g1_mul" => out_fn!(zkvm_bn254_g1_mul, 64, &p(&b("point")), &p(&b("scalar"))),
        "zkvm_bn254_pairing" => {
            let v = b("pairs");
            let (ptr, len) = pairs::<Bn254PairingPair>(&v);
            verdict_fn!(zkvm_bn254_pairing, ptr, len)
        }
        "zkvm_kzg_point_eval" => verdict_fn!(
            zkvm_kzg_point_eval,
            &p(&b("commitment")),
            &p(&b("z")),
            &p(&b("y")),
            &p(&b("proof"))
        ),
        "zkvm_bls12_g1_add" => out_fn!(zkvm_bls12_g1_add, 96, &p(&b("p1")), &p(&b("p2"))),
        "zkvm_bls12_g2_add" => out_fn!(zkvm_bls12_g2_add, 192, &p(&b("p1")), &p(&b("p2"))),
        "zkvm_bls12_g1_msm" => {
            let v = b("pairs");
            let (ptr, len) = pairs::<Bls12G1MsmPair>(&v);
            out_fn!(zkvm_bls12_g1_msm, 96, ptr, len)
        }
        "zkvm_bls12_g2_msm" => {
            let v = b("pairs");
            let (ptr, len) = pairs::<Bls12G2MsmPair>(&v);
            out_fn!(zkvm_bls12_g2_msm, 192, ptr, len)
        }
        "zkvm_bls12_pairing" => {
            let v = b("pairs");
            let (ptr, len) = pairs::<Bls12PairingPair>(&v);
            verdict_fn!(zkvm_bls12_pairing, ptr, len)
        }
        "zkvm_bls12_map_fp_to_g1" => out_fn!(zkvm_bls12_map_fp_to_g1, 96, &p(&b("fp"))),
        "zkvm_bls12_map_fp2_to_g2" => out_fn!(zkvm_bls12_map_fp2_to_g2, 192, &p(&b("fp"))),
        f => return Err(format!("no runner for {f}")),
    };
    match (expect, got) {
        ("OK", Got::Out(ZKVM_EOK, out)) if out == b("out") => Ok(()),
        ("OK", Got::Out(s, out)) => Err(format!("status {s}, out {}", hex::encode(out))),
        ("EFAIL", Got::Out(s, _)) | ("EFAIL", Got::Verdict(s, _)) if s != ZKVM_EOK => Ok(()),
        ("TRUE", Got::Verdict(ZKVM_EOK, true)) => Ok(()),
        ("REJECT", Got::Verdict(s, v)) if s != ZKVM_EOK || !v => Ok(()),
        (e, Got::Out(s, out)) => Err(format!(
            "expected {e}: status {s}, out {}",
            hex::encode(out)
        )),
        (e, Got::Verdict(s, v)) => Err(format!("expected {e}: status {s}, verified {v}")),
    }
}
