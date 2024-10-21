# Pico - The Brevis zkVM

## Codebase Structure
- `vm` includes core zkVM codes
  - `examples` includes examples that demonstrate the usage of the VMs;
  - `chips` includes various chips that could be (re)used by various VMs like RISC-V, Recursion, or any other Application-Specific VM (as precompiles or coprocessors);
  - `compiler` includes compilers as the application-specific component that compiles the source code (Rust codes, verifier circuits, etc.) to machine code that could be emulated by the target VM;
  - `configs` includes configuration files on different fields, different hash function used and different hyperparameters of proving protocol for VMs with different purposes or at different stages;
  - `emulator` includes emulators that takes programs output by `compilers` as input and generate emulation records for proving by `machines`;
  - `instances` includes instantiations for `chiptype`, `compiler`, `config` and `machine`;
  - `machine` includes main proving logic of Pico;
  - `primitives` includes consts and types used across Pico;
- `docs` includes documentations during development of Pico;
- `.github/workflows/rust.yml` includes code Github tests before merging branches to main;


## Development Process
- Branch Creation
  - Create a new feature/bug-fix/refactoring branch (e.g., `feat-a`/`fix-a`/`refactor-a`) from the `main` branch.
  - Ensure all code additions or changes are committed to this branch.
- Formatting
  - Before submitting a PR, run `make fmt` to format your code and maintain consistency.
- PR Creation
  - Open a PR against the `main` or other branch.
  - Provide a brief and clear description of the modifications in the PR description (e.g., what was changed, why it was changed).
- Review and Testing
  - Assign at least one relavent reviewer to the PR for code review.
  - Ensure all CI tests in `.github/workflows/rust.yml` pass successfully.
- Merging to `main`
  - Once the PR is approved and tests pass, merge the branch into the `main`.
  - The `main` branch reflects the current stable version of Pico.
- Post-Merge
  - Branches are automatically deleted after being merged to `main`.
