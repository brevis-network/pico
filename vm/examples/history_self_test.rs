//! The device self-test of the history loaders: for each history dump named (`history_dump`), the
//! kernel library's `cuda_history_self_test` uploads its fill, program table and stream rows,
//! rebuilds every stream on the current device under each exception lookup and compares it row
//! by row with the dump's; a last launch names another fill than the dump's and must be refused
//! with the identity bit alone. Exits non-zero unless every row of every dump is equal, the loaders
//! set no error bit, and the other fill is refused.
//!
//! ```text
//! CUDA_VISIBLE_DEVICES=2 cargo run --release -p pico-vm --example history_self_test -- \
//!   dumps/chunk-1.hdump
//! ```

use std::{ffi::c_void, fs::File, io::BufReader, mem::offset_of, path::PathBuf, process::ExitCode};

use pico_gpu_api::history_self_test::cuda_history_self_test;
use pico_vm::emulator::riscv::{
    history_dump::{Dump, Section, STREAMS},
    history_fill::{
        describe_errors, FillDescriptor, FillIdentity, ERRORS, HISTORY_LAYOUT, INSTRUCTION_ROW,
    },
};

const STREAM_COUNT: usize = STREAMS.len();

/// What one launch of the self-test returns: per stream the rows rebuilt, the rows that differ and
/// the first that does, and the loaders' error word.
struct Launch {
    rebuilt: [u64; STREAM_COUNT],
    mismatched: [u64; STREAM_COUNT],
    first: [u64; STREAM_COUNT],
    error_word: u32,
}

fn main() -> ExitCode {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if paths.is_empty() {
        eprintln!("name the history dumps to check");
        return ExitCode::from(2);
    }
    let mut equal = true;
    for path in &paths {
        match check(path) {
            Ok(same) => equal &= same,
            Err(err) => {
                eprintln!("{}: {err}", path.display());
                equal = false;
            }
        }
    }
    println!(
        "{}",
        if equal {
            "every stream equal"
        } else {
            "FAILED"
        }
    );
    if equal {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn check(path: &PathBuf) -> Result<bool, String> {
    let file = File::open(path).map_err(|err| err.to_string())?;
    let dump = Dump::read(&mut BufReader::new(file)).map_err(|err| err.to_string())?;
    let section = |tag: Section| {
        dump.section(tag)
            .ok_or_else(|| format!("the dump holds no {tag:?} section"))
    };
    let (_, fill) = section(Section::Fill)?;
    let (_, program) = section(Section::Program)?;
    let (_, base) = section(Section::ProgramBase)?;
    let word = |at: usize| u64::from_le_bytes(base[at..at + 8].try_into().expect("8 bytes"));
    let (pc_base, key) = (word(0), word(8));
    let mut rows = Vec::with_capacity(STREAMS.len());
    let mut counts = Vec::with_capacity(STREAMS.len());
    for (tag, _) in STREAMS {
        let (row_bytes, bytes) = section(tag)?;
        rows.push(bytes.as_ptr().cast::<c_void>());
        counts.push((bytes.len() / row_bytes) as u64);
    }
    println!("{}: chunk {}", path.display(), dump.chunk);
    let launch = |bitmap: u32, expected: Option<&FillIdentity>| -> Result<Launch, String> {
        let mut launch = Launch {
            rebuilt: [0; STREAM_COUNT],
            mismatched: [0; STREAM_COUNT],
            first: [0; STREAM_COUNT],
            error_word: 0,
        };
        let status = unsafe {
            cuda_history_self_test(
                HISTORY_LAYOUT,
                fill.as_ptr(),
                fill.len() as u64,
                program.as_ptr().cast(),
                (program.len() / INSTRUCTION_ROW) as u64,
                pc_base,
                key,
                rows.as_ptr(),
                counts.as_ptr(),
                bitmap,
                expected.map_or(std::ptr::null(), |expected| {
                    std::ptr::from_ref(expected).cast()
                }),
                launch.rebuilt.as_mut_ptr(),
                launch.mismatched.as_mut_ptr(),
                launch.first.as_mut_ptr(),
                &mut launch.error_word,
            )
        };
        if status.code != 0 {
            return Err(format!("the self-test failed: {}", String::from(&status)));
        }
        Ok(launch)
    };
    let mut equal = true;
    for (bitmap, lookup) in [(0, "search"), (1, "bitmap")] {
        let Launch {
            rebuilt,
            mismatched,
            first,
            error_word,
        } = launch(bitmap, None)?;
        for (stream, (_, name)) in STREAMS.iter().enumerate() {
            let same = rebuilt[stream] == counts[stream] && mismatched[stream] == 0;
            equal &= same;
            let mut line = format!("  {lookup:<6} {name:<14} {:>10} rows", counts[stream]);
            if rebuilt[stream] != counts[stream] {
                line += &format!(", {} rebuilt", rebuilt[stream]);
            }
            if mismatched[stream] != 0 {
                line += &format!(
                    ", {} differ, the first at {}",
                    mismatched[stream], first[stream]
                );
            }
            println!("{line}{}", if same { "" } else { "  MISMATCH" });
        }
        if error_word != 0 {
            println!(
                "  the loaders set error word {error_word:#x} ({})",
                describe_errors(error_word)
            );
            equal = false;
        }
    }
    let mut other = identity_of(fill)?;
    other.nonce ^= 1;
    let refused = launch(0, Some(&other))?;
    let identity_bit = 1
        << ERRORS
            .iter()
            .position(|name| *name == "identity")
            .expect("an identity bit");
    let refused_alone = refused.error_word == identity_bit && refused.rebuilt == [0; STREAM_COUNT];
    println!(
        "  a launch for another fill: error word {:#x} ({}){}",
        refused.error_word,
        describe_errors(refused.error_word),
        if refused_alone { "" } else { "  NOT REFUSED" }
    );
    equal &= refused_alone;
    Ok(equal)
}

/// The identity a dump's fill was made for, from its descriptor.
fn identity_of(fill: &[u8]) -> Result<FillIdentity, String> {
    let at = offset_of!(FillDescriptor, identity);
    let bytes = fill
        .get(at..at + size_of::<FillIdentity>())
        .ok_or("the fill is shorter than its descriptor")?;
    let word = |at: usize, width: usize| {
        bytes[at..at + width]
            .iter()
            .rev()
            .fold(0u64, |value, &byte| value << 8 | u64::from(byte))
    };
    Ok(FillIdentity {
        chunk: word(offset_of!(FillIdentity, chunk), 4) as u32,
        steps: word(offset_of!(FillIdentity, steps), 4) as u32,
        nonce: word(offset_of!(FillIdentity, nonce), 8),
    })
}
