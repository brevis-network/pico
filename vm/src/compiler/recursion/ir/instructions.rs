use super::{
    Array, CircuitV2FriFoldInput, CircuitV2FriFoldOutput, Config, Ext, Felt, FriFoldInput,
    MemIndex, Ptr, TracedVec, Usize, Var,
};
use crate::recursion::air::RecursionPublicValues;

/// An intermeddiate instruction set for implementing programs.
///
/// Programs written in the DSL can compile both to the recursive zkVM and the R1CS or Plonk-ish
/// circuits.
#[derive(Debug, Clone)]
pub enum DslIr<CF: Config> {
    // Immediates.
    /// Assigns an immediate to a variable (var = imm).
    ImmV(Var<CF::N>, CF::N),
    /// Assigns a field immediate to a field element (felt = field imm).
    ImmF(Felt<CF::F>, CF::F),
    /// Assigns an ext field immediate to an extension field element (ext = ext field imm).
    ImmE(Ext<CF::F, CF::EF>, CF::EF),

    // Additions.
    /// Add two variables (var = var + var).
    AddV(Var<CF::N>, Var<CF::N>, Var<CF::N>),
    /// Add a variable and an immediate (var = var + imm).
    AddVI(Var<CF::N>, Var<CF::N>, CF::N),
    /// Add two field elements (felt = felt + felt).
    AddF(Felt<CF::F>, Felt<CF::F>, Felt<CF::F>),
    /// Add a field element and a field immediate (felt = felt + field imm).
    AddFI(Felt<CF::F>, Felt<CF::F>, CF::F),
    /// Add two extension field elements (ext = ext + ext).
    AddE(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>),
    /// Add an extension field element and an ext field immediate (ext = ext + ext field imm).
    AddEI(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, CF::EF),
    /// Add an extension field element and a field element (ext = ext + felt).
    AddEF(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, Felt<CF::F>),
    /// Add an extension field element and a field immediate (ext = ext + field imm).
    AddEFI(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, CF::F),
    /// Add a field element and an ext field immediate (ext = felt + ext field imm).
    AddEFFI(Ext<CF::F, CF::EF>, Felt<CF::F>, CF::EF),

    // Subtractions.
    /// Subtracts two variables (var = var - var).
    SubV(Var<CF::N>, Var<CF::N>, Var<CF::N>),
    /// Subtracts a variable and an immediate (var = var - imm).
    SubVI(Var<CF::N>, Var<CF::N>, CF::N),
    /// Subtracts an immediate and a variable (var = imm - var).
    SubVIN(Var<CF::N>, CF::N, Var<CF::N>),
    /// Subtracts two field elements (felt = felt - felt).
    SubF(Felt<CF::F>, Felt<CF::F>, Felt<CF::F>),
    /// Subtracts a field element and a field immediate (felt = felt - field imm).
    SubFI(Felt<CF::F>, Felt<CF::F>, CF::F),
    /// Subtracts a field immediate and a field element (felt = field imm - felt).
    SubFIN(Felt<CF::F>, CF::F, Felt<CF::F>),
    /// Subtracts two extension field elements (ext = ext - ext).
    SubE(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>),
    /// Subtrancts an extension field element and an extension field immediate (ext = ext - ext
    /// field imm).
    SubEI(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, CF::EF),
    /// Subtracts an extension field immediate and an extension field element (ext = ext field imm
    /// - ext).
    SubEIN(Ext<CF::F, CF::EF>, CF::EF, Ext<CF::F, CF::EF>),
    /// Subtracts an extension field element and a field immediate (ext = ext - field imm).
    SubEFI(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, CF::F),
    /// Subtracts an extension field element and a field element (ext = ext - felt).
    SubEF(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, Felt<CF::F>),

    // Multiplications.
    /// Multiplies two variables (var = var * var).
    MulV(Var<CF::N>, Var<CF::N>, Var<CF::N>),
    /// Multiplies a variable and an immediate (var = var * imm).
    MulVI(Var<CF::N>, Var<CF::N>, CF::N),
    /// Multiplies two field elements (felt = felt * felt).
    MulF(Felt<CF::F>, Felt<CF::F>, Felt<CF::F>),
    /// Multiplies a field element and a field immediate (felt = felt * field imm).
    MulFI(Felt<CF::F>, Felt<CF::F>, CF::F),
    /// Multiplies two extension field elements (ext = ext * ext).
    MulE(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>),
    /// Multiplies an extension field element and an extension field immediate (ext = ext * ext
    /// field imm).
    MulEI(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, CF::EF),
    /// Multiplies an extension field element and a field immediate (ext = ext * field imm).
    MulEFI(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, CF::F),
    /// Multiplies an extension field element and a field element (ext = ext * felt).
    MulEF(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, Felt<CF::F>),

    // Divisions.
    /// Divides two variables (var = var / var).
    DivF(Felt<CF::F>, Felt<CF::F>, Felt<CF::F>),
    /// Divides a field element and a field immediate (felt = felt / field imm).
    DivFI(Felt<CF::F>, Felt<CF::F>, CF::F),
    /// Divides a field immediate and a field element (felt = field imm / felt).
    DivFIN(Felt<CF::F>, CF::F, Felt<CF::F>),
    /// Divides two extension field elements (ext = ext / ext).
    DivE(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>),
    /// Divides an extension field element and an extension field immediate (ext = ext / ext field
    /// imm).
    DivEI(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, CF::EF),
    /// Divides and extension field immediate and an extension field element (ext = ext field imm /
    /// ext).
    DivEIN(Ext<CF::F, CF::EF>, CF::EF, Ext<CF::F, CF::EF>),
    /// Divides an extension field element and a field immediate (ext = ext / field imm).
    DivEFI(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, CF::F),
    /// Divides a field immediate and an extension field element (ext = field imm / ext).
    DivEFIN(Ext<CF::F, CF::EF>, CF::F, Ext<CF::F, CF::EF>),
    /// Divides an extension field element and a field element (ext = ext / felt).
    DivEF(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>, Felt<CF::F>),

    // Negations.
    /// Negates a variable (var = -var).
    NegV(Var<CF::N>, Var<CF::N>),
    /// Negates a field element (felt = -felt).
    NegF(Felt<CF::F>, Felt<CF::F>),
    /// Negates an extension field element (ext = -ext).
    NegE(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>),
    /// Inverts a variable (var = 1 / var).
    InvV(Var<CF::N>, Var<CF::N>),
    /// Inverts a field element (felt = 1 / felt).
    InvF(Felt<CF::F>, Felt<CF::F>),
    /// Inverts an extension field element (ext = 1 / ext).
    InvE(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>),

    // Control flow.
    /// Executes a for loop with the parameters (start step value, end step value, step size, step
    /// variable, body).
    For(
        Box<(
            Usize<CF::N>,
            Usize<CF::N>,
            CF::N,
            Var<CF::N>,
            TracedVec<DslIr<CF>>,
        )>,
    ),
    /// Executes an equal conditional branch with the parameters (lhs var, rhs var, then body, else
    /// body).
    IfEq(
        Box<(
            Var<CF::N>,
            Var<CF::N>,
            TracedVec<DslIr<CF>>,
            TracedVec<DslIr<CF>>,
        )>,
    ),
    /// Executes a not equal conditional branch with the parameters (lhs var, rhs var, then body,
    /// else body).
    IfNe(
        Box<(
            Var<CF::N>,
            Var<CF::N>,
            TracedVec<DslIr<CF>>,
            TracedVec<DslIr<CF>>,
        )>,
    ),
    /// Executes an equal conditional branch with the parameters (lhs var, rhs imm, then body, else
    /// body).
    IfEqI(
        Box<(
            Var<CF::N>,
            CF::N,
            TracedVec<DslIr<CF>>,
            TracedVec<DslIr<CF>>,
        )>,
    ),
    /// Executes a not equal conditional branch with the parameters (lhs var, rhs imm, then body,
    /// else body).
    IfNeI(
        Box<(
            Var<CF::N>,
            CF::N,
            TracedVec<DslIr<CF>>,
            TracedVec<DslIr<CF>>,
        )>,
    ),
    /// Break out of a for loop.
    Break,

    // Assertions.
    /// Assert that two variables are equal (var == var).
    AssertEqV(Var<CF::N>, Var<CF::N>),
    /// Assert that two variables are not equal (var != var).
    AssertNeV(Var<CF::N>, Var<CF::N>),
    /// Assert that two field elements are equal (felt == felt).
    AssertEqF(Felt<CF::F>, Felt<CF::F>),
    /// Assert that two field elements are not equal (felt != felt).
    AssertNeF(Felt<CF::F>, Felt<CF::F>),
    /// Assert that two extension field elements are equal (ext == ext).
    AssertEqE(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>),
    /// Assert that two extension field elements are not equal (ext != ext).
    AssertNeE(Ext<CF::F, CF::EF>, Ext<CF::F, CF::EF>),
    /// Assert that a variable is equal to an immediate (var == imm).
    AssertEqVI(Var<CF::N>, CF::N),
    /// Assert that a variable is not equal to an immediate (var != imm).
    AssertNeVI(Var<CF::N>, CF::N),
    /// Assert that a field element is equal to a field immediate (felt == field imm).
    AssertEqFI(Felt<CF::F>, CF::F),
    /// Assert that a field element is not equal to a field immediate (felt != field imm).
    AssertNeFI(Felt<CF::F>, CF::F),
    /// Assert that an extension field element is equal to an extension field immediate (ext == ext
    /// field imm).
    AssertEqEI(Ext<CF::F, CF::EF>, CF::EF),
    /// Assert that an extension field element is not equal to an extension field immediate (ext !=
    /// ext field imm).
    AssertNeEI(Ext<CF::F, CF::EF>, CF::EF),

    // Memory instructions.
    /// Allocate (ptr, len, size) a memory slice of length len
    Alloc(Ptr<CF::N>, Usize<CF::N>, usize),
    /// Load variable (var, ptr, index)
    LoadV(Var<CF::N>, Ptr<CF::N>, MemIndex<CF::N>),
    /// Load field element (var, ptr, index)
    LoadF(Felt<CF::F>, Ptr<CF::N>, MemIndex<CF::N>),
    /// Load extension field
    LoadE(Ext<CF::F, CF::EF>, Ptr<CF::N>, MemIndex<CF::N>),
    /// Store variable at address
    StoreV(Var<CF::N>, Ptr<CF::N>, MemIndex<CF::N>),
    /// Store field element at address
    StoreF(Felt<CF::F>, Ptr<CF::N>, MemIndex<CF::N>),
    /// Store extension field at address
    StoreE(Ext<CF::F, CF::EF>, Ptr<CF::N>, MemIndex<CF::N>),

    /// Force reduction of field elements in circuit.
    ReduceE(Ext<CF::F, CF::EF>),

    // Bits.
    /// Decompose a variable into size bits (bits = num2bits(var, size)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsV(Var<CF::N>, usize, Vec<Var<CF::N>>),
    /// Decompose a field element into bits (bits = num2bits(felt)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsF(Felt<CF::F>, Vec<Var<CF::N>>),
    /// Convert a Felt to a Var in a circuit. Avoids decomposing to bits and then reconstructing.
    CircuitFelt2Var(Felt<CF::F>, Var<CF::N>),

    // Hashing.
    /// Permutes an array of baby bear elements using Poseidon2 (output = p2_permute(array)).
    Poseidon2PermuteBabyBear(Box<(Array<CF, Felt<CF::F>>, Array<CF, Felt<CF::F>>)>),
    /// Compresses two baby bear element arrays using Poseidon2 (output = p2_compress(array1,
    /// array2)).
    Poseidon2CompressBabyBear(
        Box<(
            Array<CF, Felt<CF::F>>,
            Array<CF, Felt<CF::F>>,
            Array<CF, Felt<CF::F>>,
        )>,
    ),
    /// Absorb an array of baby bear elements for a specified hash instance.
    Poseidon2AbsorbBabyBear(Var<CF::N>, Array<CF, Felt<CF::F>>),
    /// Finalize and return the hash digest of a specified hash instance.
    Poseidon2FinalizeBabyBear(Var<CF::N>, Array<CF, Felt<CF::F>>),
    /// Permutes an array of Bn254 elements using Poseidon2 (output = p2_permute(array)). Should
    /// only be used when target is a gnark circuit.
    CircuitPoseidon2Permute([Var<CF::N>; 3]),
    /// Permutates an array of BabyBear elements in the circuit.
    CircuitPoseidon2PermuteBabyBear(Box<[Felt<CF::F>; 16]>),
    /// Permutates an array of BabyBear elements in the circuit using the skinny precompile.
    CircuitV2Poseidon2PermuteBabyBear(Box<([Felt<CF::F>; 16], [Felt<CF::F>; 16])>),
    /// Commits the public values.
    CircuitV2CommitPublicValues(Box<RecursionPublicValues<Felt<CF::F>>>),

    // Miscellaneous instructions.
    /// Decompose hint operation of a usize into an array. (output = num2bits(usize)).
    HintBitsU(Array<CF, Var<CF::N>>, Usize<CF::N>),
    /// Decompose hint operation of a variable into an array. (output = num2bits(var)).
    HintBitsV(Array<CF, Var<CF::N>>, Var<CF::N>),
    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    HintBitsF(Array<CF, Var<CF::N>>, Felt<CF::F>),
    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    CircuitV2HintBitsF(Vec<Felt<CF::F>>, Felt<CF::F>),
    /// Prints a variable.
    PrintV(Var<CF::N>),
    /// Prints a field element.
    PrintF(Felt<CF::F>),
    /// Prints an extension field element.
    PrintE(Ext<CF::F, CF::EF>),
    /// Throws an error.
    Error(),

    /// Converts an ext to a slice of felts.
    HintExt2Felt(Array<CF, Felt<CF::F>>, Ext<CF::F, CF::EF>),
    /// Hint the length of the next array.
    HintLen(Var<CF::N>),
    /// Hint an array of variables.
    HintVars(Array<CF, Var<CF::N>>),
    /// Hint an array of field elements.
    HintFelts(Array<CF, Felt<CF::F>>),
    /// Hint an array of extension field elements.
    HintExts(Array<CF, Ext<CF::F, CF::EF>>),
    /// Hint an array of field elements.
    CircuitV2HintFelts(Vec<Felt<CF::F>>),
    /// Hint an array of extension field elements.
    CircuitV2HintExts(Vec<Ext<CF::F, CF::EF>>),
    /// Witness a variable. Should only be used when target is a gnark circuit.
    WitnessVar(Var<CF::N>, u32),
    /// Witness a field element. Should only be used when target is a gnark circuit.
    WitnessFelt(Felt<CF::F>, u32),
    /// Witness an extension field element. Should only be used when target is a gnark circuit.
    WitnessExt(Ext<CF::F, CF::EF>, u32),
    /// Label a field element as the ith public input.
    Commit(Felt<CF::F>, Var<CF::N>),
    /// Registers a field element to the public inputs.
    RegisterPublicValue(Felt<CF::F>),
    /// Operation to halt the program. Should be the last instruction in the program.
    Halt,

    // Public inputs for circuits.
    /// Asserts that the inputted var is equal the circuit's vkey hash public input. Should only be
    /// used when target is a gnark circuit.
    CircuitCommitVkeyHash(Var<CF::N>),
    /// Asserts that the inputted var is equal the circuit's commited values digest public input.
    /// Should only be used when target is a gnark circuit.
    CircuitCommitCommitedValuesDigest(Var<CF::N>),

    // FRI specific instructions.
    /// Executes a FRI fold operation. 1st field is the size of the fri fold input array.  2nd
    /// field is the fri fold input array.  See [`FriFoldInput`] for more details.
    FriFold(Var<CF::N>, Array<CF, FriFoldInput<CF>>),
    // FRI specific instructions.
    /// Executes a FRI fold operation. Input is the fri fold input array.  See [`FriFoldInput`] for
    /// more details.
    CircuitV2FriFold(Box<(CircuitV2FriFoldOutput<CF>, CircuitV2FriFoldInput<CF>)>),
    /// Select's a variable based on a condition. (select(cond, true_val, false_val) => output).
    /// Should only be used when target is a gnark circuit.
    CircuitSelectV(Var<CF::N>, Var<CF::N>, Var<CF::N>, Var<CF::N>),
    /// Select's a field element based on a condition. (select(cond, true_val, false_val) =>
    /// output). Should only be used when target is a gnark circuit.
    CircuitSelectF(Var<CF::N>, Felt<CF::F>, Felt<CF::F>, Felt<CF::F>),
    /// Select's an extension field element based on a condition. (select(cond, true_val,
    /// false_val) => output). Should only be used when target is a gnark circuit.
    CircuitSelectE(
        Var<CF::N>,
        Ext<CF::F, CF::EF>,
        Ext<CF::F, CF::EF>,
        Ext<CF::F, CF::EF>,
    ),
    /// Converts an ext to a slice of felts. Should only be used when target is a gnark circuit.
    CircuitExt2Felt([Felt<CF::F>; 4], Ext<CF::F, CF::EF>),
    /// Converts a slice of felts to an ext. Should only be used when target is a gnark circuit.
    CircuitFelts2Ext([Felt<CF::F>; 4], Ext<CF::F, CF::EF>),

    // Debugging instructions.
    /// Executes less than (var = var < var).  This operation is NOT constrained.
    LessThan(Var<CF::N>, Var<CF::N>, Var<CF::N>),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTracker(String),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Enter(String),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Exit,

    // Reverse bits exponentiation.
    ExpReverseBitsLen(Ptr<CF::N>, Var<CF::N>, Var<CF::N>),
    /// Reverse bits exponentiation. Output, base, exponent bits.
    CircuitV2ExpReverseBits(Felt<CF::F>, Felt<CF::F>, Vec<Felt<CF::F>>),
}
