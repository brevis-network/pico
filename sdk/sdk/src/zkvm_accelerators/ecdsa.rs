//! ECDSA on secp256k1 and secp256r1, through Pico's patched `k256` and `p256`.

use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, RecoveryId, Signature as K256Signature,
    VerifyingKey as K256VerifyingKey,
};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};

use super::{arg, out, ZkvmStatus, ZKVM_EFAIL, ZKVM_EOK};

/// `zkvm_status zkvm_secp256k1_verify(const zkvm_secp256k1_hash* msg, const
/// zkvm_secp256k1_signature* sig, const zkvm_secp256k1_pubkey* pubkey, bool* verified)`.
/// `sig` is `r || s`, either `s` half accepted; `pubkey` is `x || y`. A malformed signature or
/// key verifies false.
///
/// # Safety
///
/// `msg` points to 32 bytes, `sig` and `pubkey` to 64, `verified` to a `bool`.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_secp256k1_verify(
    msg: *const [u8; 32],
    sig: *const [u8; 64],
    pubkey: *const [u8; 64],
    verified: *mut bool,
) -> ZkvmStatus {
    const F: &str = "zkvm_secp256k1_verify";
    let (msg, sig, pubkey) = (
        arg(msg, F, "msg"),
        arg(sig, F, "sig"),
        arg(pubkey, F, "pubkey"),
    );
    let verified = out(verified, F, "verified");
    verified.write(
        (|| {
            let sig = K256Signature::from_slice(&sig).ok()?;
            let sig = sig.normalize_s().unwrap_or(sig);
            let key = K256VerifyingKey::from_sec1_bytes(&sec1(&pubkey)).ok()?;
            Some(key.verify_prehash(&msg, &sig).is_ok())
        })()
        .unwrap_or(false),
    );
    ZKVM_EOK
}

/// `zkvm_status zkvm_secp256k1_ecrecover(const zkvm_secp256k1_hash* msg, const
/// zkvm_secp256k1_signature* sig, uint8_t recid, zkvm_secp256k1_pubkey* output)`: the public key
/// `x || y` (not the address). A high `s` is accepted, as the precompile does.
///
/// # Safety
///
/// `msg` points to 32 bytes, `sig` and `output` to 64.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_secp256k1_ecrecover(
    msg: *const [u8; 32],
    sig: *const [u8; 64],
    recid: u8,
    output: *mut [u8; 64],
) -> ZkvmStatus {
    const F: &str = "zkvm_secp256k1_ecrecover";
    let (msg, sig) = (arg(msg, F, "msg"), arg(sig, F, "sig"));
    let output = out(output, F, "output");
    let key = (|| {
        let sig = K256Signature::from_slice(&sig).ok()?;
        let mut recid = RecoveryId::from_byte(recid)?;
        // Recovery wants the low `s`; negating `s` flips the parity of R's y.
        let sig = match sig.normalize_s() {
            Some(low) => {
                recid = RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced());
                low
            }
            None => sig,
        };
        K256VerifyingKey::recover_from_prehash(&msg, &sig, recid).ok()
    })();
    let Some(key) = key else {
        return ZKVM_EFAIL;
    };
    let point = key.to_encoded_point(false);
    output.write(point.as_bytes()[1..].try_into().unwrap());
    ZKVM_EOK
}

/// `zkvm_status zkvm_secp256r1_verify(const zkvm_secp256r1_hash* msg, const
/// zkvm_secp256r1_signature* sig, const zkvm_secp256r1_pubkey* pubkey, bool* verified)`
/// (EIP-7951). A malformed signature or key verifies false.
///
/// # Safety
///
/// `msg` points to 32 bytes, `sig` and `pubkey` to 64, `verified` to a `bool`.
#[cfg_attr(target_os = "zkvm", no_mangle)]
pub unsafe extern "C" fn zkvm_secp256r1_verify(
    msg: *const [u8; 32],
    sig: *const [u8; 64],
    pubkey: *const [u8; 64],
    verified: *mut bool,
) -> ZkvmStatus {
    const F: &str = "zkvm_secp256r1_verify";
    let (msg, sig, pubkey) = (
        arg(msg, F, "msg"),
        arg(sig, F, "sig"),
        arg(pubkey, F, "pubkey"),
    );
    let verified = out(verified, F, "verified");
    verified.write(
        (|| {
            let sig = P256Signature::from_slice(&sig).ok()?;
            let key = P256VerifyingKey::from_sec1_bytes(&sec1(&pubkey)).ok()?;
            Some(key.verify_prehash(&msg, &sig).is_ok())
        })()
        .unwrap_or(false),
    );
    ZKVM_EOK
}

/// `x || y` as an uncompressed SEC1 key.
fn sec1(xy: &[u8; 64]) -> [u8; 65] {
    let mut key = [0x04; 65];
    key[1..].copy_from_slice(xy);
    key
}
