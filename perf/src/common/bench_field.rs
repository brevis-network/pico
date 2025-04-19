use anyhow::{anyhow, Error};
use strum::EnumIter;

#[derive(Debug, Clone, Copy, EnumIter)]
pub enum BenchField {
    BabyBear,
    KoalaBear,
}

impl BenchField {
    pub fn to_str(&self) -> &'static str {
        match self {
            BenchField::BabyBear => "bb",
            BenchField::KoalaBear => "kb",
        }
    }

    pub fn url_path(&self) -> &'static str {
        match self {
            BenchField::BabyBear => "babybear_gnark",
            BenchField::KoalaBear => "koalabear_gnark",
        }
    }
}

impl std::str::FromStr for BenchField {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bb" => Ok(BenchField::BabyBear),
            "kb" => Ok(BenchField::KoalaBear),
            _ => Err(anyhow!("unsupported field for gnark: {}", s)),
        }
    }
}
