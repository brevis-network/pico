//! The guest program and its input, as the command line names them.
//!
//! An input is typed so that its encoding is the guest's: `u64:100` becomes the bytes
//! `read_as::<u64>()` decodes, where the raw form of the same value is `0x6400000000000000`,
//! little-endian and eight bytes wide. The raw form stays for input the guest decodes itself.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use pico_prover::Stdin;

#[derive(Clone, Parser)]
pub struct GuestArgs {
    /// ELF file path
    #[clap(long)]
    pub elf: PathBuf,

    /// One guest input, `<type>:<value>`, `0x<hex>` or `file:<path>`; repeat it in the order the
    /// guest reads
    ///
    /// `<type>:<value>` is encoded as the guest's `read_as::<type>()` decodes it, for u8, u16, u32,
    /// u64, u128, i8, i16, i32, i64, i128, bool and string: `u64:100` is what the guest reads with
    /// `read_as::<u64>()`. `0x<hex>` and `file:<path>` are raw bytes, as the guest's `read_vec()`
    /// returns them.
    #[clap(long, value_parser = parse_input, value_name = "INPUT")]
    pub input: Vec<InputElement>,
}

impl GuestArgs {
    pub fn read_elf(&self) -> Result<Vec<u8>> {
        std::fs::read(&self.elf).with_context(|| format!("cannot read `{}`", self.elf.display()))
    }

    pub fn stdin(&self) -> Stdin {
        let mut stdin = Stdin::new();
        for element in &self.input {
            element.write_to(&mut stdin);
        }
        stdin
    }
}

/// One element of the guest's input.
#[derive(Debug, Clone, PartialEq)]
pub enum InputElement {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    Bool(bool),
    String(String),
    Raw(Vec<u8>),
}

impl InputElement {
    fn write_to(&self, stdin: &mut Stdin) {
        match self {
            Self::U8(v) => stdin.write(v),
            Self::U16(v) => stdin.write(v),
            Self::U32(v) => stdin.write(v),
            Self::U64(v) => stdin.write(v),
            Self::U128(v) => stdin.write(v),
            Self::I8(v) => stdin.write(v),
            Self::I16(v) => stdin.write(v),
            Self::I32(v) => stdin.write(v),
            Self::I64(v) => stdin.write(v),
            Self::I128(v) => stdin.write(v),
            Self::Bool(v) => stdin.write(v),
            Self::String(v) => stdin.write(v),
            Self::Raw(bytes) => stdin.write_bytes(bytes),
        };
    }
}

pub fn parse_input(s: &str) -> Result<InputElement, String> {
    if let Some(hex) = s.strip_prefix("0x") {
        return decode_hex(hex).map(InputElement::Raw);
    }
    let Some((kind, value)) = s.split_once(':') else {
        // A bare number is the mistake the typed form exists to prevent: its width is what the
        // guest's decode depends on, and nothing here can know it.
        return Err(if s.parse::<i128>().is_ok() {
            format!(
                "`{s}` does not say how wide the guest's integer is: write `u32:{s}` or \
                 `u64:{s}`, whichever the guest reads"
            )
        } else {
            format!("`{s}` is not an input: write `<type>:<value>`, `0x<hex>` or `file:<path>`")
        });
    };
    match kind {
        "u8" => parsed(value, InputElement::U8),
        "u16" => parsed(value, InputElement::U16),
        "u32" => parsed(value, InputElement::U32),
        "u64" => parsed(value, InputElement::U64),
        "u128" => parsed(value, InputElement::U128),
        "i8" => parsed(value, InputElement::I8),
        "i16" => parsed(value, InputElement::I16),
        "i32" => parsed(value, InputElement::I32),
        "i64" => parsed(value, InputElement::I64),
        "i128" => parsed(value, InputElement::I128),
        "bool" => parsed(value, InputElement::Bool),
        "string" => Ok(InputElement::String(value.to_string())),
        "file" => std::fs::read(value)
            .map(InputElement::Raw)
            .map_err(|e| format!("cannot read `{value}`: {e}")),
        _ => Err(format!(
            "unknown input type `{kind}`: expected u8, u16, u32, u64, u128, i8, i16, i32, i64, \
             i128, bool, string or file"
        )),
    }
}

fn parsed<T: std::str::FromStr>(
    value: &str,
    element: fn(T) -> InputElement,
) -> Result<InputElement, String>
where
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map(element)
        .map_err(|e| format!("`{value}`: {e}"))
}

fn decode_hex(digits: &str) -> Result<Vec<u8>, String> {
    hex::decode(digits).map_err(|e| format!("`0x{digits}` is not hex: {e}"))
}

pub fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typed_integer_keeps_its_width() {
        assert_eq!(parse_input("u64:100"), Ok(InputElement::U64(100)));
        assert_eq!(parse_input("u32:100"), Ok(InputElement::U32(100)));
        assert_eq!(parse_input("i8:-1"), Ok(InputElement::I8(-1)));
        assert_eq!(parse_input("bool:true"), Ok(InputElement::Bool(true)));
        assert_eq!(
            parse_input("string:a:b"),
            Ok(InputElement::String("a:b".into()))
        );
    }

    #[test]
    fn hex_is_raw_bytes_in_the_order_written() {
        assert_eq!(
            parse_input("0x6400000000000000"),
            Ok(InputElement::Raw(vec![100, 0, 0, 0, 0, 0, 0, 0]))
        );
        assert_eq!(parse_input("0x"), Ok(InputElement::Raw(vec![])));
        assert_eq!(encode_hex(&[0x0a, 0xff]), "0aff");
    }

    #[test]
    fn a_bare_number_is_refused_with_the_typed_spelling() {
        let err = parse_input("10").unwrap_err();
        assert!(
            err.contains("`u32:10`") && err.contains("`u64:10`"),
            "{err}"
        );
    }

    #[test]
    fn malformed_input_is_refused() {
        assert!(parse_input("u8:256").is_err());
        assert!(parse_input("u32:-1").is_err());
        assert!(parse_input("f32:1.0").is_err());
        assert!(parse_input("0x123").is_err());
        assert!(parse_input("0xzz").is_err());
        assert!(parse_input("0xé0").is_err());
        assert!(parse_input("0x+1+f").is_err());
        assert!(parse_input("0x-1").is_err());
        assert!(parse_input("file:/nonexistent/pico-input").is_err());
    }

    #[test]
    fn a_file_is_one_raw_element() {
        let path = std::env::temp_dir().join(format!("pico_cli_input_{}", std::process::id()));
        std::fs::write(&path, [1, 2, 3]).unwrap();
        let parsed = parse_input(&format!("file:{}", path.display()));
        std::fs::remove_file(&path).ok();
        assert_eq!(parsed, Ok(InputElement::Raw(vec![1, 2, 3])));
    }
}
