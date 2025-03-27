use pico_sdk::{
    client::{BabyBearProverClient, DefaultProverClient},
    m31_client::M31RiscvProverClient,
};

pub enum SDKProverClient {
    BabyBearProver(BabyBearProverClient),
    KoalaBearProver(DefaultProverClient),
    M31Prover(M31RiscvProverClient),
}

impl SDKProverClient {
    pub fn new(elf: &[u8], field: &str) -> Self {
        match field {
            "bb" => SDKProverClient::BabyBearProver(BabyBearProverClient::new(elf)),
            "kb" => SDKProverClient::KoalaBearProver(DefaultProverClient::new(elf)),
            "m31" => SDKProverClient::M31Prover(M31RiscvProverClient::new(elf)),
            _ => panic!("Unsupported field type: {}", field),
        }
    }
}
