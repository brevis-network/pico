//! What the record and trace goldens share: local-memory windows in a total order, the record
//! golden's digest, and each guest's lines of a golden file.
//!
//! The windows, the chunk's and each precompile event's, are drained from hash maps whose hasher
//! has fixed keys but is a different function on a target with hardware AES, so their order is
//! fixed for a build and not the same on every target; sorted, they are. `record_digests.txt` and
//! `trace_digests.txt` are written through these, so any change here moves them.
//!
//! A golden file is its header, then each guest's lines in the order the guests run, each line
//! starting with the guest's name and a tab, so a guest's check compares and rewrites its own.

use std::{
    io::Write,
    path::Path,
    sync::{Mutex, PoisonError},
};

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryLocalEvent,
    emulator::riscv::syscalls::precompiles::PrecompileEvent,
};

/// FNV-1a over the bincode encoding.
pub fn digest<T: serde::Serialize + ?Sized>(value: &T) -> u64 {
    struct Fnv(u64);
    impl Write for Fnv {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            for byte in buf {
                self.0 ^= u64::from(*byte);
                self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut fnv = Fnv(0xcbf2_9ce4_8422_2325);
    bincode::serialize_into(&mut fnv, value).expect("serialize");
    fnv.0
}

/// Windows in a total order: the maps they are drained from iterate in no fixed one.
pub fn sort_windows(windows: &mut [MemoryLocalEvent]) {
    windows.sort_unstable_by_key(|w| {
        let (i, f) = (w.initial_mem_access, w.final_mem_access);
        (
            w.addr,
            i.chunk,
            i.timestamp,
            i.value,
            f.chunk,
            f.timestamp,
            f.value,
        )
    });
}

/// The local-memory windows `event` carries.
pub fn local_mem_access_mut(event: &mut PrecompileEvent) -> &mut Vec<MemoryLocalEvent> {
    match event {
        PrecompileEvent::ShaExtend(e) => &mut e.local_mem_access,
        PrecompileEvent::ShaCompress(e) => &mut e.local_mem_access,
        PrecompileEvent::KeccakPermute(e) => &mut e.local_mem_access,
        PrecompileEvent::EdDecompress(e) => &mut e.local_mem_access,
        PrecompileEvent::EdAdd(e)
        | PrecompileEvent::Secp256k1Add(e)
        | PrecompileEvent::Secp256r1Add(e)
        | PrecompileEvent::Bn254Add(e)
        | PrecompileEvent::Bls12381Add(e) => &mut e.local_mem_access,
        PrecompileEvent::Secp256k1Double(e)
        | PrecompileEvent::Secp256r1Double(e)
        | PrecompileEvent::Bn254Double(e)
        | PrecompileEvent::Bls12381Double(e) => &mut e.local_mem_access,
        PrecompileEvent::Secp256k1Decompress(e)
        | PrecompileEvent::Secp256r1Decompress(e)
        | PrecompileEvent::K256Decompress(e)
        | PrecompileEvent::Bls12381Decompress(e) => &mut e.local_mem_access,
        PrecompileEvent::Bn254Fp(e)
        | PrecompileEvent::Bls12381Fp(e)
        | PrecompileEvent::Secp256k1Fp(e) => &mut e.local_mem_access,
        PrecompileEvent::Bn254Fp2AddSub(e) | PrecompileEvent::Bls12381Fp2AddSub(e) => {
            &mut e.local_mem_access
        }
        PrecompileEvent::Bn254Fp2Mul(e) | PrecompileEvent::Bls12381Fp2Mul(e) => {
            &mut e.local_mem_access
        }
        PrecompileEvent::Uint256Mul(e) => &mut e.local_mem_access,
        PrecompileEvent::Poseidon2Permute(e) => &mut e.local_mem_access,
    }
}

/// The lines of the golden file `pinned` that are `guest`'s, each with its line number.
pub fn section<'a>(pinned: &'a str, guest: &'a str) -> impl Iterator<Item = (usize, &'a str)> {
    pinned
        .lines()
        .enumerate()
        .filter(move |(_, line)| !line.starts_with('#') && line.split('\t').next() == Some(guest))
        .map(|(index, line)| (index + 1, line))
}

/// The golden file `header` and the lines of each guest in `order` make, as a rewrite writes it.
pub fn assemble<'a>(header: &str, lines: impl IntoIterator<Item = &'a str>) -> String {
    format!(
        "{header}{}\n",
        lines.into_iter().collect::<Vec<_>>().join("\n")
    )
}

/// The golden file `pinned` rewritten from its own lines of the guests in `order`: `pinned`
/// itself when it holds `header` and no other line, in order.
pub fn in_order(pinned: &str, header: &str, order: &[&str]) -> String {
    assemble(
        header,
        order
            .iter()
            .flat_map(|guest| section(pinned, guest).map(|(_, line)| line)),
    )
}

/// Rewrites the golden file at `path` with `guest`'s lines replaced by `lines`, every other
/// guest's kept as the file holds them. The rewrites of one process take turns; two processes
/// rewriting one file at once can lose a guest's lines.
pub fn rewrite_section(path: &Path, header: &str, order: &[&str], guest: &str, lines: &[String]) {
    static TURN: Mutex<()> = Mutex::new(());
    let _turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    let pinned = std::fs::read_to_string(path).unwrap_or_default();
    let mut kept = Vec::new();
    for name in order {
        if *name == guest {
            kept.extend(lines.iter().map(String::as_str));
        } else {
            kept.extend(section(&pinned, name).map(|(_, line)| line));
        }
    }
    std::fs::write(path, assemble(header, kept))
        .unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
}
