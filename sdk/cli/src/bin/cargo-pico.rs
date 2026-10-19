fn main() -> anyhow::Result<()> {
    pico_cli::run(std::env::args_os())
}
