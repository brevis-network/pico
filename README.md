# Pico-VM (tentative)

## Codebase Structure
- `chips` includes various chips that could be (re)used by various VMs like RISC-V, Recursion, or any other Application-Specific VM (ASVM);
- `compiler` includes compilers as the application-specific component that compiles the source code (Rust codes, verifier circuits, etc.) to machine code that could be emulated by the target VM;
- `configs` includes configuration files on different fields, different hash function used and different hyperparameters of proving protocol for VMs with different purposes or at different stages;
- `docs` includes documentations during development of VM;
- `examples` includes examples that demonstrate the usage of the VMs;
- `machine` includes main proving logic of VMs based on [Plonky3](https://github.com/Plonky3/Plonky3);

## Development
- `make fmt` could be used to format the current code.
- `make lint` could be used to check the code with lint tools.
