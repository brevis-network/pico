use pico_sdk::{
    client::{BabyBearProverClient, DefaultProverClient},
    m31_client::M31RiscvProverClient,
    vk_client::{BabyBearProveVKClient, KoalaBearProveVKClient},
};

pub enum SDKProverClient {
    BabyBearProver(BabyBearProverClient),
    KoalaBearProver(DefaultProverClient),
    BabyBearProveVKProver(BabyBearProveVKClient),
    KoalaBearProveVKProver(KoalaBearProveVKClient),
    M31Prover(M31RiscvProverClient),
}

impl SDKProverClient {
    pub fn new(elf: &[u8], field: &str, vk: bool) -> Self {
        match field {
            "bb" => {
                if vk {
                    SDKProverClient::BabyBearProveVKProver(BabyBearProveVKClient::new(elf))
                } else {
                    SDKProverClient::BabyBearProver(BabyBearProverClient::new(elf))
                }
            }
            "kb" => {
                if vk {
                    SDKProverClient::KoalaBearProveVKProver(KoalaBearProveVKClient::new(elf))
                } else {
                    SDKProverClient::KoalaBearProver(DefaultProverClient::new(elf))
                }
            }
            "m31" => {
                if vk {
                    panic!("Unsupported vk for m31");
                } else {
                    SDKProverClient::M31Prover(M31RiscvProverClient::new(elf))
                }
            }
            _ => panic!("Unsupported field type: {}", field),
        }
    }
}
