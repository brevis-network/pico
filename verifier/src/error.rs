/// Why a proof, a VK bundle or an envelope was refused.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The VK bundle is malformed: magic, version, encoding or contents.
    #[error("VK bundle: {0}")]
    Bundle(String),
    /// The proof envelope is malformed: magic, version, encoding, proof or vk bytes.
    #[error("proof envelope: {0}")]
    Envelope(String),
    /// The VK bundle names a whitelist root other than the one the caller trusts.
    #[error("the VK bundle's whitelist root is not the trusted one")]
    UntrustedVkRoot,
    /// A whitelist member's Merkle path does not reach the trusted root.
    #[error("whitelist member at leaf {index} does not verify against the trusted root")]
    MemberOffRoot { index: usize },
    /// The supplied vk has no merged preprocessed commitment.
    #[error("supplied vk is not a recursion (merged-preprocessed) key")]
    NotRecursionVk,
    /// The supplied vk's body does not hash to the pre_hash it carries.
    #[error("supplied vk body does not hash to its self-reported pre_hash")]
    VkBodyMismatch,
    /// The supplied vk's identity is not a whitelist member.
    #[error("supplied vk is not in the whitelist")]
    NotWhitelisted,
    /// The STARK verify failed.
    #[error("root proof failed STARK verify: {0}")]
    Stark(String),
    /// No public-value vector of the recursion length.
    #[error("proof carries no recursion public values")]
    NoRecursionPublicValues,
    /// `flag_complete != 1`.
    #[error("{label} proof is not complete (flag_complete != 1)")]
    Incomplete { label: String },
    #[error("{label} riscv_vk_digest limb {limb} does not match the trusted RiscvVmVk digest")]
    RiscvVkDigestMismatch { label: String, limb: usize },
    #[error("{label} vk_root limb {limb} does not match the trusted whitelist root")]
    VkRootMismatch { label: String, limb: usize },
    #[error("{label} PV digest limb {limb} does not match the recomputed hash")]
    PvDigestMismatch { label: String, limb: usize },
    /// A `committed_value_digest` slot holds something other than one byte.
    #[error("committed_value_digest limb {index} is {value}, not a byte")]
    DigestLimbNotByte { index: usize, value: u32 },
    /// The committed bytes do not hash to the digest the proof attests to.
    #[error("the committed values do not match the proof's committed_value_digest")]
    CommittedValuesUnbound,
}
