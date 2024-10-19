use super::{
    Array, CircuitV2FriFoldInput, CircuitV2FriFoldOutput, Ext, Felt, FriFoldInput, MemIndex, Ptr,
    TracedVec, Usize, Var,
};
use crate::{configs::config::RecursionGenericConfig, recursion::air::RecursionPublicValues};

/// An intermeddiate instruction set for implementing programs.
///
/// Programs written in the DSL can compile both to the recursive zkVM and the R1CS or Plonk-ish
/// circuits.
#[derive(Debug, Clone)]
pub enum DslIr<RC: RecursionGenericConfig> {
    // Immediates.
    /// Assigns an immediate to a variable (var = imm).
    ImmV(Var<RC::N>, RC::N),
    /// Assigns a field immediate to a field element (felt = field imm).
    ImmF(Felt<RC::F>, RC::F),
    /// Assigns an ext field immediate to an extension field element (ext = ext field imm).
    ImmE(Ext<RC::F, RC::EF>, RC::EF),

    // Additions.
    /// Add two variables (var = var + var).
    AddV(Var<RC::N>, Var<RC::N>, Var<RC::N>),
    /// Add a variable and an immediate (var = var + imm).
    AddVI(Var<RC::N>, Var<RC::N>, RC::N),
    /// Add two field elements (felt = felt + felt).
    AddF(Felt<RC::F>, Felt<RC::F>, Felt<RC::F>),
    /// Add a field element and a field immediate (felt = felt + field imm).
    AddFI(Felt<RC::F>, Felt<RC::F>, RC::F),
    /// Add two extension field elements (ext = ext + ext).
    AddE(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>),
    /// Add an extension field element and an ext field immediate (ext = ext + ext field imm).
    AddEI(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, RC::EF),
    /// Add an extension field element and a field element (ext = ext + felt).
    AddEF(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, Felt<RC::F>),
    /// Add an extension field element and a field immediate (ext = ext + field imm).
    AddEFI(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, RC::F),
    /// Add a field element and an ext field immediate (ext = felt + ext field imm).
    AddEFFI(Ext<RC::F, RC::EF>, Felt<RC::F>, RC::EF),

    // Subtractions.
    /// Subtracts two variables (var = var - var).
    SubV(Var<RC::N>, Var<RC::N>, Var<RC::N>),
    /// Subtracts a variable and an immediate (var = var - imm).
    SubVI(Var<RC::N>, Var<RC::N>, RC::N),
    /// Subtracts an immediate and a variable (var = imm - var).
    SubVIN(Var<RC::N>, RC::N, Var<RC::N>),
    /// Subtracts two field elements (felt = felt - felt).
    SubF(Felt<RC::F>, Felt<RC::F>, Felt<RC::F>),
    /// Subtracts a field element and a field immediate (felt = felt - field imm).
    SubFI(Felt<RC::F>, Felt<RC::F>, RC::F),
    /// Subtracts a field immediate and a field element (felt = field imm - felt).
    SubFIN(Felt<RC::F>, RC::F, Felt<RC::F>),
    /// Subtracts two extension field elements (ext = ext - ext).
    SubE(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>),
    /// Subtrancts an extension field element and an extension field immediate (ext = ext - ext
    /// field imm).
    SubEI(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, RC::EF),
    /// Subtracts an extension field immediate and an extension field element (ext = ext field imm
    /// - ext).
    SubEIN(Ext<RC::F, RC::EF>, RC::EF, Ext<RC::F, RC::EF>),
    /// Subtracts an extension field element and a field immediate (ext = ext - field imm).
    SubEFI(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, RC::F),
    /// Subtracts an extension field element and a field element (ext = ext - felt).
    SubEF(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, Felt<RC::F>),

    // Multiplications.
    /// Multiplies two variables (var = var * var).
    MulV(Var<RC::N>, Var<RC::N>, Var<RC::N>),
    /// Multiplies a variable and an immediate (var = var * imm).
    MulVI(Var<RC::N>, Var<RC::N>, RC::N),
    /// Multiplies two field elements (felt = felt * felt).
    MulF(Felt<RC::F>, Felt<RC::F>, Felt<RC::F>),
    /// Multiplies a field element and a field immediate (felt = felt * field imm).
    MulFI(Felt<RC::F>, Felt<RC::F>, RC::F),
    /// Multiplies two extension field elements (ext = ext * ext).
    MulE(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>),
    /// Multiplies an extension field element and an extension field immediate (ext = ext * ext
    /// field imm).
    MulEI(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, RC::EF),
    /// Multiplies an extension field element and a field immediate (ext = ext * field imm).
    MulEFI(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, RC::F),
    /// Multiplies an extension field element and a field element (ext = ext * felt).
    MulEF(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, Felt<RC::F>),

    // Divisions.
    /// Divides two variables (var = var / var).
    DivF(Felt<RC::F>, Felt<RC::F>, Felt<RC::F>),
    /// Divides a field element and a field immediate (felt = felt / field imm).
    DivFI(Felt<RC::F>, Felt<RC::F>, RC::F),
    /// Divides a field immediate and a field element (felt = field imm / felt).
    DivFIN(Felt<RC::F>, RC::F, Felt<RC::F>),
    /// Divides two extension field elements (ext = ext / ext).
    DivE(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>),
    /// Divides an extension field element and an extension field immediate (ext = ext / ext field
    /// imm).
    DivEI(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, RC::EF),
    /// Divides and extension field immediate and an extension field element (ext = ext field imm /
    /// ext).
    DivEIN(Ext<RC::F, RC::EF>, RC::EF, Ext<RC::F, RC::EF>),
    /// Divides an extension field element and a field immediate (ext = ext / field imm).
    DivEFI(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, RC::F),
    /// Divides a field immediate and an extension field element (ext = field imm / ext).
    DivEFIN(Ext<RC::F, RC::EF>, RC::F, Ext<RC::F, RC::EF>),
    /// Divides an extension field element and a field element (ext = ext / felt).
    DivEF(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>, Felt<RC::F>),

    // Negations.
    /// Negates a variable (var = -var).
    NegV(Var<RC::N>, Var<RC::N>),
    /// Negates a field element (felt = -felt).
    NegF(Felt<RC::F>, Felt<RC::F>),
    /// Negates an extension field element (ext = -ext).
    NegE(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>),
    /// Inverts a variable (var = 1 / var).
    InvV(Var<RC::N>, Var<RC::N>),
    /// Inverts a field element (felt = 1 / felt).
    InvF(Felt<RC::F>, Felt<RC::F>),
    /// Inverts an extension field element (ext = 1 / ext).
    InvE(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>),

    // Control flow.
    /// Executes a for loop with the parameters (start step value, end step value, step size, step
    /// variable, body).
    For(
        Box<(
            Usize<RC::N>,
            Usize<RC::N>,
            RC::N,
            Var<RC::N>,
            TracedVec<DslIr<RC>>,
        )>,
    ),
    /// Executes an equal conditional branch with the parameters (lhs var, rhs var, then body, else
    /// body).
    IfEq(
        Box<(
            Var<RC::N>,
            Var<RC::N>,
            TracedVec<DslIr<RC>>,
            TracedVec<DslIr<RC>>,
        )>,
    ),
    /// Executes a not equal conditional branch with the parameters (lhs var, rhs var, then body,
    /// else body).
    IfNe(
        Box<(
            Var<RC::N>,
            Var<RC::N>,
            TracedVec<DslIr<RC>>,
            TracedVec<DslIr<RC>>,
        )>,
    ),
    /// Executes an equal conditional branch with the parameters (lhs var, rhs imm, then body, else
    /// body).
    IfEqI(
        Box<(
            Var<RC::N>,
            RC::N,
            TracedVec<DslIr<RC>>,
            TracedVec<DslIr<RC>>,
        )>,
    ),
    /// Executes a not equal conditional branch with the parameters (lhs var, rhs imm, then body,
    /// else body).
    IfNeI(
        Box<(
            Var<RC::N>,
            RC::N,
            TracedVec<DslIr<RC>>,
            TracedVec<DslIr<RC>>,
        )>,
    ),
    /// Break out of a for loop.
    Break,

    // Assertions.
    /// Assert that two variables are equal (var == var).
    AssertEqV(Var<RC::N>, Var<RC::N>),
    /// Assert that two variables are not equal (var != var).
    AssertNeV(Var<RC::N>, Var<RC::N>),
    /// Assert that two field elements are equal (felt == felt).
    AssertEqF(Felt<RC::F>, Felt<RC::F>),
    /// Assert that two field elements are not equal (felt != felt).
    AssertNeF(Felt<RC::F>, Felt<RC::F>),
    /// Assert that two extension field elements are equal (ext == ext).
    AssertEqE(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>),
    /// Assert that two extension field elements are not equal (ext != ext).
    AssertNeE(Ext<RC::F, RC::EF>, Ext<RC::F, RC::EF>),
    /// Assert that a variable is equal to an immediate (var == imm).
    AssertEqVI(Var<RC::N>, RC::N),
    /// Assert that a variable is not equal to an immediate (var != imm).
    AssertNeVI(Var<RC::N>, RC::N),
    /// Assert that a field element is equal to a field immediate (felt == field imm).
    AssertEqFI(Felt<RC::F>, RC::F),
    /// Assert that a field element is not equal to a field immediate (felt != field imm).
    AssertNeFI(Felt<RC::F>, RC::F),
    /// Assert that an extension field element is equal to an extension field immediate (ext == ext
    /// field imm).
    AssertEqEI(Ext<RC::F, RC::EF>, RC::EF),
    /// Assert that an extension field element is not equal to an extension field immediate (ext !=
    /// ext field imm).
    AssertNeEI(Ext<RC::F, RC::EF>, RC::EF),

    // Memory instructions.
    /// Allocate (ptr, len, size) a memory slice of length len
    Alloc(Ptr<RC::N>, Usize<RC::N>, usize),
    /// Load variable (var, ptr, index)
    LoadV(Var<RC::N>, Ptr<RC::N>, MemIndex<RC::N>),
    /// Load field element (var, ptr, index)
    LoadF(Felt<RC::F>, Ptr<RC::N>, MemIndex<RC::N>),
    /// Load extension field
    LoadE(Ext<RC::F, RC::EF>, Ptr<RC::N>, MemIndex<RC::N>),
    /// Store variable at address
    StoreV(Var<RC::N>, Ptr<RC::N>, MemIndex<RC::N>),
    /// Store field element at address
    StoreF(Felt<RC::F>, Ptr<RC::N>, MemIndex<RC::N>),
    /// Store extension field at address
    StoreE(Ext<RC::F, RC::EF>, Ptr<RC::N>, MemIndex<RC::N>),

    /// Force reduction of field elements in circuit.
    ReduceE(Ext<RC::F, RC::EF>),

    // Bits.
    /// Decompose a variable into size bits (bits = num2bits(var, size)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsV(Var<RC::N>, usize, Vec<Var<RC::N>>),
    /// Decompose a field element into bits (bits = num2bits(felt)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsF(Felt<RC::F>, Vec<Var<RC::N>>),
    /// Convert a Felt to a Var in a circuit. Avoids decomposing to bits and then reconstructing.
    CircuitFelt2Var(Felt<RC::F>, Var<RC::N>),

    // Hashing.
    /// Permutes an array of baby bear elements using Poseidon2 (output = p2_permute(array)).
    Poseidon2PermuteBabyBear(Box<(Array<RC, Felt<RC::F>>, Array<RC, Felt<RC::F>>)>),
    /// Compresses two baby bear element arrays using Poseidon2 (output = p2_compress(array1,
    /// array2)).
    Poseidon2CompressBabyBear(
        Box<(
            Array<RC, Felt<RC::F>>,
            Array<RC, Felt<RC::F>>,
            Array<RC, Felt<RC::F>>,
        )>,
    ),
    /// Absorb an array of baby bear elements for a specified hash instance.
    Poseidon2AbsorbBabyBear(Var<RC::N>, Array<RC, Felt<RC::F>>),
    /// Finalize and return the hash digest of a specified hash instance.
    Poseidon2FinalizeBabyBear(Var<RC::N>, Array<RC, Felt<RC::F>>),
    /// Permutes an array of Bn254 elements using Poseidon2 (output = p2_permute(array)). Should
    /// only be used when target is a gnark circuit.
    CircuitPoseidon2Permute([Var<RC::N>; 3]),
    /// Permutates an array of BabyBear elements in the circuit.
    CircuitPoseidon2PermuteBabyBear(Box<[Felt<RC::F>; 16]>),
    /// Permutates an array of BabyBear elements in the circuit using the skinny precompile.
    CircuitV2Poseidon2PermuteBabyBear(Box<([Felt<RC::F>; 16], [Felt<RC::F>; 16])>),
    /// Commits the public values.
    CircuitV2CommitPublicValues(Box<RecursionPublicValues<Felt<RC::F>>>),

    // Miscellaneous instructions.
    /// Decompose hint operation of a usize into an array. (output = num2bits(usize)).
    HintBitsU(Array<RC, Var<RC::N>>, Usize<RC::N>),
    /// Decompose hint operation of a variable into an array. (output = num2bits(var)).
    HintBitsV(Array<RC, Var<RC::N>>, Var<RC::N>),
    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    HintBitsF(Array<RC, Var<RC::N>>, Felt<RC::F>),
    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    CircuitV2HintBitsF(Vec<Felt<RC::F>>, Felt<RC::F>),
    /// Prints a variable.
    PrintV(Var<RC::N>),
    /// Prints a field element.
    PrintF(Felt<RC::F>),
    /// Prints an extension field element.
    PrintE(Ext<RC::F, RC::EF>),
    /// Throws an error.
    Error(),

    /// Converts an ext to a slice of felts.
    HintExt2Felt(Array<RC, Felt<RC::F>>, Ext<RC::F, RC::EF>),
    /// Hint the length of the next array.
    HintLen(Var<RC::N>),
    /// Hint an array of variables.
    HintVars(Array<RC, Var<RC::N>>),
    /// Hint an array of field elements.
    HintFelts(Array<RC, Felt<RC::F>>),
    /// Hint an array of extension field elements.
    HintExts(Array<RC, Ext<RC::F, RC::EF>>),
    /// Hint an array of field elements.
    CircuitV2HintFelts(Vec<Felt<RC::F>>),
    /// Hint an array of extension field elements.
    CircuitV2HintExts(Vec<Ext<RC::F, RC::EF>>),
    /// Witness a variable. Should only be used when target is a gnark circuit.
    WitnessVar(Var<RC::N>, u32),
    /// Witness a field element. Should only be used when target is a gnark circuit.
    WitnessFelt(Felt<RC::F>, u32),
    /// Witness an extension field element. Should only be used when target is a gnark circuit.
    WitnessExt(Ext<RC::F, RC::EF>, u32),
    /// Label a field element as the ith public input.
    Commit(Felt<RC::F>, Var<RC::N>),
    /// Registers a field element to the public inputs.
    RegisterPublicValue(Felt<RC::F>),
    /// Operation to halt the program. Should be the last instruction in the program.
    Halt,

    // Public inputs for circuits.
    /// Asserts that the inputted var is equal the circuit's vkey hash public input. Should only be
    /// used when target is a gnark circuit.
    CircuitCommitVkeyHash(Var<RC::N>),
    /// Asserts that the inputted var is equal the circuit's commited values digest public input.
    /// Should only be used when target is a gnark circuit.
    CircuitCommitCommitedValuesDigest(Var<RC::N>),

    // FRI specific instructions.
    /// Executes a FRI fold operation. 1st field is the size of the fri fold input array.  2nd
    /// field is the fri fold input array.  See [`FriFoldInput`] for more details.
    FriFold(Var<RC::N>, Array<RC, FriFoldInput<RC>>),
    // FRI specific instructions.
    /// Executes a FRI fold operation. Input is the fri fold input array.  See [`FriFoldInput`] for
    /// more details.
    CircuitV2FriFold(Box<(CircuitV2FriFoldOutput<RC>, CircuitV2FriFoldInput<RC>)>),
    /// Select's a variable based on a condition. (select(cond, true_val, false_val) => output).
    /// Should only be used when target is a gnark circuit.
    CircuitSelectV(Var<RC::N>, Var<RC::N>, Var<RC::N>, Var<RC::N>),
    /// Select's a field element based on a condition. (select(cond, true_val, false_val) =>
    /// output). Should only be used when target is a gnark circuit.
    CircuitSelectF(Var<RC::N>, Felt<RC::F>, Felt<RC::F>, Felt<RC::F>),
    /// Select's an extension field element based on a condition. (select(cond, true_val,
    /// false_val) => output). Should only be used when target is a gnark circuit.
    CircuitSelectE(
        Var<RC::N>,
        Ext<RC::F, RC::EF>,
        Ext<RC::F, RC::EF>,
        Ext<RC::F, RC::EF>,
    ),
    /// Converts an ext to a slice of felts. Should only be used when target is a gnark circuit.
    CircuitExt2Felt([Felt<RC::F>; 4], Ext<RC::F, RC::EF>),
    /// Converts a slice of felts to an ext. Should only be used when target is a gnark circuit.
    CircuitFelts2Ext([Felt<RC::F>; 4], Ext<RC::F, RC::EF>),

    // Debugging instructions.
    /// Executes less than (var = var < var).  This operation is NOT constrained.
    LessThan(Var<RC::N>, Var<RC::N>, Var<RC::N>),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTracker(String),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Enter(String),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Exit,

    // Reverse bits exponentiation.
    ExpReverseBitsLen(Ptr<RC::N>, Var<RC::N>, Var<RC::N>),
    /// Reverse bits exponentiation. Output, base, exponent bits.
    CircuitV2ExpReverseBits(Felt<RC::F>, Felt<RC::F>, Vec<Felt<RC::F>>),
}
