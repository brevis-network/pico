use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use pico_aot_dispatch::AOT;
use pico_aot_runtime::AotError;
use sha2::{Digest, Sha256};

/// Whether [`register`] installed this binary's own generated program.
static REGISTERED: AtomicBool = AtomicBool::new(false);

/// The ELF that last passed [`ensure_generated_from`], held so that it is known again by its
/// address: a process proves one ELF block after block, and its tens of megabytes would
/// otherwise be hashed inside every proof.
static CHECKED: Mutex<Option<Arc<[u8]>>> = Mutex::new(None);

/// Registers the generated AOT program. A refused one (the bootstrap stub, or code generated
/// against another codegen stamp) installs no factory, and `EmulatorOpts::bench_riscv_ops` then
/// leaves the snapshot thread on the interpreter, so the run is slower but its records the same.
/// A conflict leaves the program registered first in place, with AOT emulation on.
pub fn register() {
    match pico_aot_runtime::register(&AOT) {
        Ok(()) => REGISTERED.store(true, Ordering::Release),
        Err(err @ AotError::Conflict { .. }) => {
            tracing::warn!("AOT emulation runs the program registered first, not this one: {err}")
        }
        Err(err) => tracing::warn!("AOT emulation is off, the snapshot thread interprets: {err}"),
    }
}

/// Refuses to prove `elf` with compiled code generated from another ELF.
///
/// The registered program runs every block of whatever ELF the process proves: the runtime
/// does not hold it against that ELF. A guest swapped without regenerating the AOT crates would
/// run its PCs through code compiled for other instructions and fail somewhere inside a proof;
/// this makes it fail when the ELF is loaded, saying what to do. With two reth guests in the
/// tree (`reth-elf` and `reth-amsterdam-elf`) and one set of AOT crates, that is one `--elf`
/// away.
///
/// Called for every block. The ELF is hashed the first time it is seen and when another one
/// comes; the same `Arc` again costs a lock and a pointer comparison.
pub(crate) fn ensure_generated_from(elf: &Arc<[u8]>, source: &str) {
    if !REGISTERED.load(Ordering::Acquire) {
        return;
    }
    if let Err(loaded) = check(elf, AOT.elf_sha256(), &CHECKED) {
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        panic!(
            "this binary's AOT program was generated from the ELF with SHA-256 {}, but {source} \
             has SHA-256 {}: regenerate the AOT crates from this ELF (`cargo run -r -p \
             pico-aot-codegen --bin generate_crates -- <elf>`) and rebuild, or build without \
             `aot-emulator`",
            hex(AOT.elf_sha256()),
            hex(loaded),
        );
    }
}

/// Whether `elf` has the digest `generated_from`; if not, the digest it has.
///
/// `checked` remembers the ELF that passed last, by holding it: while it is held no other
/// allocation can have its address, so the same pointer is the same bytes.
fn check(
    elf: &Arc<[u8]>,
    generated_from: [u8; 32],
    checked: &Mutex<Option<Arc<[u8]>>>,
) -> Result<(), [u8; 32]> {
    let mut checked = checked.lock().unwrap_or_else(|e| e.into_inner());
    if checked
        .as_ref()
        .is_some_and(|known| Arc::ptr_eq(known, elf))
    {
        return Ok(());
    }
    let loaded: [u8; 32] = Sha256::digest(&elf[..]).into();
    if loaded != generated_from {
        return Err(loaded);
    }
    *checked = Some(Arc::clone(elf));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    #[test]
    fn the_elf_the_code_was_generated_from_passes_and_is_remembered() {
        let checked = Mutex::new(None);
        let elf: Arc<[u8]> = Arc::from(&b"an ELF"[..]);
        assert_eq!(check(&elf, digest(b"an ELF"), &checked), Ok(()));
        let held = checked.lock().unwrap().clone().expect("the ELF is held");
        assert!(Arc::ptr_eq(&held, &elf));
    }

    /// The second call does not hash: it passes against a digest the bytes do not have, which
    /// only the remembered pointer can explain.
    #[test]
    fn the_same_arc_again_is_not_hashed() {
        let checked = Mutex::new(None);
        let elf: Arc<[u8]> = Arc::from(&b"an ELF"[..]);
        assert_eq!(check(&elf, digest(b"an ELF"), &checked), Ok(()));
        assert_eq!(check(&elf, [0; 32], &checked), Ok(()));
    }

    #[test]
    fn another_elf_is_refused_with_its_digest_and_forgets_nothing() {
        let checked = Mutex::new(None);
        let elf: Arc<[u8]> = Arc::from(&b"an ELF"[..]);
        let other: Arc<[u8]> = Arc::from(&b"another"[..]);
        assert_eq!(check(&elf, digest(b"an ELF"), &checked), Ok(()));
        assert_eq!(
            check(&other, digest(b"an ELF"), &checked),
            Err(digest(b"another"))
        );
        // The refused one is not remembered: it is refused again, and the first still passes
        // without being hashed.
        assert_eq!(
            check(&other, digest(b"an ELF"), &checked),
            Err(digest(b"another"))
        );
        assert_eq!(check(&elf, [0; 32], &checked), Ok(()));
    }

    /// The same bytes in another allocation are hashed, pass, and take the remembered place.
    #[test]
    fn equal_bytes_at_another_address_are_hashed() {
        let checked = Mutex::new(None);
        let elf: Arc<[u8]> = Arc::from(&b"an ELF"[..]);
        let copy: Arc<[u8]> = Arc::from(&b"an ELF"[..]);
        assert_eq!(check(&elf, digest(b"an ELF"), &checked), Ok(()));
        assert_eq!(check(&copy, [0; 32], &checked), Err(digest(b"an ELF")));
        assert_eq!(check(&copy, digest(b"an ELF"), &checked), Ok(()));
        assert!(Arc::ptr_eq(
            checked.lock().unwrap().as_ref().unwrap(),
            &copy
        ));
    }
}
