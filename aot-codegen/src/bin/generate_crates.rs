use std::{env, path::PathBuf};

fn main() {
    let elf_path = env::args()
        .nth(1)
        .or_else(|| env::var("PICO_AOT_ELF").ok())
        .unwrap_or_else(|| {
            eprintln!("usage: generate_crates <elf_path> [out_dir]");
            eprintln!("or set PICO_AOT_ELF");
            std::process::exit(2);
        });

    let out_dir = env::args()
        .nth(2)
        .or_else(|| env::var("PICO_AOT_OUT_DIR").ok())
        .unwrap_or_else(|| "aot-generated".to_string());

    let blocks_per_chunk = env::var("PICO_AOT_BLOCKS_PER_CHUNK")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

    let target_chunk_count = env::var("PICO_AOT_TARGET_CHUNKS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

    let max_chunk_count = env::var("PICO_AOT_MAX_CHUNKS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());

    let max_block_instructions = env::var("PICO_AOT_MAX_BLOCK_INSNS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());

    let max_superblock_instructions = env::var("PICO_AOT_MAX_SUPERBLOCK_INSNS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());

    let save_metrics = env::var("PICO_AOT_SAVE_METRICS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);

    if save_metrics {
        eprintln!("Metrics collection enabled - metrics will be saved to metrics.json");
    }

    let elf_path = PathBuf::from(elf_path);
    let elf_bytes = std::fs::read(&elf_path).unwrap_or_else(|e| {
        panic!("Failed to read ELF at {}: {}", elf_path.display(), e);
    });

    let program_info = pico_aot_codegen::parse_elf(&elf_bytes);

    let mut config = pico_aot_codegen::AotConfig::new(PathBuf::from(out_dir.clone()));

    if let Some(blocks_per_chunk) = blocks_per_chunk {
        config = config.with_chunk_size(blocks_per_chunk);
    }
    if let Some(target_chunk_count) = target_chunk_count {
        config = config.with_target_chunk_count(Some(target_chunk_count));
    }
    if let Some(max_chunk_count) = max_chunk_count {
        config = config.with_max_chunk_count(max_chunk_count);
    }
    if let Some(max_block_instructions) = max_block_instructions {
        config = config.with_max_block_instructions(max_block_instructions);
    }
    if let Some(max_superblock_instructions) = max_superblock_instructions {
        config = config.with_max_superblock_instructions(max_superblock_instructions);
    }

    pico_aot_codegen::AotCompiler::new(program_info, config)
        .compile()
        .expect("AOT crate generation failed");
}
