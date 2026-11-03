# ACT4: the RISC-V architectural tests zkevm-test-monitor runs

zkevm-test-monitor (eth-act) checks a zkVM against ACT4, the RISC-V Architectural Certification
Tests. The EF zkVM handbook asks for every test of the zkevm-standards target to execute, prove and
verify. This directory holds those tests as built for Pico, and the configuration they were
built with.

A test computes its results and compares them with the Sail reference model's, which are compiled
into it. It then writes `PASS` or `FAIL` to the public values (fd 3) and halts, with exit code 0
after `PASS` and 1 after `FAIL`. So what a run commits is the test's verdict, and nothing that runs
the tests has to know what each one checks.

## What is here

`act4-elfs-4.1.0-pico-rv64im-zicclsm.tar.xz` (0.7 MB, 19 MB unpacked) holds the 72 tests of the
target, RV64IM_Zicclsm, as `elfs/<suite>/<test>.elf`, one directory per ACT4 suite:

| Suite | Tests | |
|---|---|---|
| `I` | 51 | must pass |
| `M` | 13 | must pass |
| `Misalign` | 8 | known failures: Pico rejects misaligned loads and stores |

`pico-rv64im-zicclsm/` is the Pico configuration they were built with. zkevm-test-monitor reads it
as `zkvms/pico/isa-configs/pico-rv64im-zicclsm/`.

* `pico-rv64im-zicclsm.yaml`: the UDB configuration of the target.
* `link.ld`: one R+X segment for all code, padded with `nop`, then one R+W segment, at
  `0x4000_0000`.
* `rvmodel_macros.h`: how a test writes its verdict, commits the public-values digest and halts.
* `sail.json`: the reference model's memory map.
* `test_config.yaml`: the tools.

## Where they run

`tests::act4` in pico-prover runs all 72:

* each test of `I` and `M` executes and proves to the riscv phase, which verifies the proof, and
  both must commit `PASS`;
* each test of `Misalign` executes and must still fail. The first one that passes fails the module
  instead, and the suite then moves into `MUST_PASS`, so that all 72 are required from then on.

```bash
cargo test --release -p pico-prover -- --test-threads=1 --nocapture tests::act4::
```

The first test to need the ELFs checks the archive's SHA-256 against the one `tests::act4` pins,
then unpacks it into `target/<profile>/act4-elfs-<hash>/`. Later runs, of any test binary of that
profile, reuse the directory, and `cargo clean` removes it. The test runs `tar -xJf`, so `tar` and
`xz` must be on the path. To take one ELF out by hand, for `cargo pico prove --elf`:

```bash
mkdir -p /tmp/act4 && tar -xJf act4/act4-elfs-4.1.0-pico-rv64im-zicclsm.tar.xz -C /tmp/act4
# /tmp/act4/elfs/I/I-add-00.elf, ...
```

CI runs it on the CPU prover as `CPU · ACT4 RV64IM_Zicclsm (64 pass, 8 known failures)` in
`test-prover.yml`. On the GPU prover, run the same module with `--features cuda` on a machine with a
card.

## How they were built

* ACT4 4.1.0, riscv-arch-test `6e8a45123f14cebfb3df151a0e7b849b4389b33b`.
* GCC 15.1 and binutils 2.45 (riscv-gnu-toolchain 2025.08.08), and Sail 0.13.1.
* zkevm-test-monitor's ACT4 image, with its Pico integration and this configuration.
* The monitor's `patch_elfs.py` then replaced the data words ACT4 leaves in executable sections with
  `nop`. Pico decodes every word of an executable segment when it loads an ELF.

To rebuild them, run the monitor's ISA tests for Pico with this directory as Pico's configuration.
Then pack `out/pico/elfs/target/rv64i/{I,M,Misalign}` with GNU tar, as below, so that the same ELFs
always give the same archive. Put its new SHA-256 into `tests::act4`, and give the file a new name
when its contents change.

```bash
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="2026-10-28 00:00:00Z" --format=gnu \
    --transform "s,^,elfs/," -C out/pico/elfs/target/rv64i -cf - I M Misalign \
  | xz -9e -T1 > act4/act4-elfs-4.1.0-pico-rv64im-zicclsm.tar.xz
```
