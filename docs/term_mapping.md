| R0             | SP1                          | Brevis             | Component |
|----------------|------------------------------|--------------------|-----------|
| Segment        | Shard                        | Element            | machine   |
| Session        |                              | Ensemble           | machine   |
| SegmentReceipt | ShardProof                   | BaseProof          | machine   |
|                | MachineProof                 | EnsembleProof      | machine   |
|                | StarkMachine + MachineProver | BaseProver         | machine   |
|                | Verifier                     | BaseVerifier       | machine   |
|                | SP1Prover                    | (Pico)Machine      | machine   |
| prove_segment  | prove_core                   | prove              | machine   |
| lift + join    | compress + shrink            | combine + compress | machine   |
|                | AirInteraction               | AirInteraction     | chip      |
|                | Interaction                  | LookupPayload      | chip      |
|                | send                         | looking            | chip      |
|                | receive                      | looked             | chip      |
|                | InteractionBuilder           | ChipProxyBuilder   | chip      |
|                | RiscvAir / RecursionAir      | ChipType           | chip      |
|                | Chip                         | MetaChip           | chip      |
|                | MachineAir                   | ChipBehavior       | chip      |
| identity_p254  | wrap_bn254                   | embed_bn254        | compiler  |
| stark_to_snark | wrap_plonk_bn254             | convert_groth16    | compiler  |
|                | Program                      | Program            | compiler  |
|                | Executor                     | Emulator           | compiler  |
|                | OpeningProof                 | PcsProof           | compiler  |
|                | OpeningError                 | PcsError           | compiler  |