// Rust Monero Library
// Written in 2021 by
//   h4sh3d <h4sh3d@protonmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//

//! Amounts, denominations, and errors types and arithmetic.
//!
//! This implementation is based on
//! [`rust-bitcoin`](https://github.com/rust-bitcoin/rust-bitcoin/blob/20f1543f79066886b3ae12fff4f5bb58dd8cc1ab/src/util/amount.rs)
//! `Amount` and `SignedAmount` implementations.
//!

use std::cmp::Ordering;
use std::default;
use std::fmt::{self, Write};
use std::ops;
use std::str::FromStr;

use thiserror::Error;

/// Potential errors encountered when recovering the amount of an [`OwnedTxOut`].
///
/// [`OwnedTxOut`]: crate::blockdata::transaction::OwnedTxOut
///
#[derive(Error, Debug, PartialEq)]
pub enum RecoveryError {
    /// Index of output is out of range.
    #[error("The index is out of range")]
    IndexOutOfRange,
    /// Missing signature for the output.
    #[error("Missing signature for the output")]
    MissingSignature,
    /// Invalid commitment.
    #[error("Invalid commitment")]
    InvalidCommitment,
}

/// A set of denominations in which amounts can be expressed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Denomination {
    /// XMR
    Monero,
    /// millinero
    Millinero,
    /// micronero
    Micronero,
    /// nanonero
    Nanonero,
    /// piconero
    Piconero,
}

impl Denomination {
    /// The number of decimal places more than a piconero.
    fn precision(self) -> i32 {
        match self {
            Denomination::Monero => -12,
            Denomination::Millinero => -9,
            Denomination::Micronero => -6,
            Denomination::Nanonero => -3,
            Denomination::Piconero => 0,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Denomination::Monero => "XMR",
            Denomination::Millinero => "millinero",
            Denomination::Micronero => "micronero",
            Denomination::Nanonero => "nanonero",
            Denomination::Piconero => "piconero",
        })
    }
}

impl FromStr for Denomination {
    type Err = ParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "XMR" => Ok(Denomination::Monero),
            "millinero" => Ok(Denomination::Millinero),
            "micronero" => Ok(Denomination::Micronero),
            "nanonero" => Ok(Denomination::Nanonero),
            "piconero" => Ok(Denomination::Piconero),
            d => Err(ParsingError::UnknownDenomination(d.to_owned())),
        }
    }
}

/// An error during amount parsing.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParsingError {
    /// Amount is negative.
    #[error("Amount is negative")]
    Negative,
    /// Amount is too big to fit inside the type.
    #[error("Amount is too big to fit inside the type")]
    TooBig,
    /// Amount has higher precision than supported by the type.
    #[error("Amount has higher precision than supported by the type")]
    TooPrecise,
    /// Invalid number format.
    #[error("Invalid number format")]
    InvalidFormat,
    /// Input string was too large.
    #[error("Input string was too large")]
    InputTooLarge,
    /// Invalid character in input.
    #[error("Invalid character in input: {0}")]
    InvalidCharacter(char),
    /// The denomination was unknown.
    #[error("The denomination was unknown: {0}")]
    UnknownDenomination(String),
}

fn is_too_precise(s: &str, precision: usize) -> bool {
    s.contains('.') || precision >= s.len() || s.chars().rev().take(precision).any(|d| d != '0')
}

/// Parse decimal string in the given denomination into a piconero value and a bool indicator for a
/// negative amount.
fn parse_signed_to_piconero(mut s: &str, denom: Denomination) -> Result<(bool, u64), ParsingError> {
    if s.is_empty() {
        return Err(ParsingError::InvalidFormat);
    }
    if s.len() > 50 {
        return Err(ParsingError::InputTooLarge);
    }

    let is_negative = s.starts_with('-');
    if is_negative {
        if s.len() == 1 {
            return Err(ParsingError::InvalidFormat);
        }
        s = &s[1..];
    }

    let max_decimals = {
        // The difference in precision between native (piconero) and desired denomination.
        let precision_diff = -denom.precision();
        if precision_diff < 0 {
            // If precision diff is negative, this means we are parsing
            // into a less precise amount. That is not allowed unless
            // there are no decimals and the last digits are zeroes as
            // many as the difference in precision.
            let last_n = precision_diff.abs() as usize;
            if is_too_precise(s, last_n) {
                return Err(ParsingError::TooPrecise);
            }
            s = &s[0..s.len() - last_n];
            0
        } else {
            precision_diff
        }
    };

    let mut decimals = None;
    let mut value: u64 = 0; // as piconero
    for c in s.chars() {
        match c {
            '0'..='9' => {
                // Do `value = 10 * value + digit`, catching overflows.
                match 10_u64.checked_mul(value) {
                    None => return Err(ParsingError::TooBig),
                    Some(val) => match val.checked_add((c as u8 - b'0') as u64) {
                        None => return Err(ParsingError::TooBig),
                        Some(val) => value = val,
                    },
                }
                // Increment the decimal digit counter if past decimal.
                decimals = match decimals {
                    None => None,
                    Some(d) if d < max_decimals => Some(d + 1),
                    _ => return Err(ParsingError::TooPrecise),
                };
            }
            '.' => match decimals {
                None => decimals = Some(0),
                // Double decimal dot.
                _ => return Err(ParsingError::InvalidFormat),
            },
            c => return Err(ParsingError::InvalidCharacter(c)),
        }
    }

    // Decimally shift left by `max_decimals - decimals`.
    let scale_factor = max_decimals - decimals.unwrap_or(0);
    for _ in 0..scale_factor {
        value = match 10_u64.checked_mul(value) {
            Some(v) => v,
            None => return Err(ParsingError::TooBig),
        };
    }

    Ok((is_negative, value))
}

/// Format the given piconero amount in the given denomination without including the denomination.
fn fmt_piconero_in(
    piconero: u64,
    negative: bool,
    f: &mut dyn fmt::Write,
    denom: Denomination,
) -> fmt::Result {
    if negative {
        f.write_str("-")?;
    }

    let precision = denom.precision();
    match precision.cmp(&0) {
        Ordering::Greater => {
            // add zeroes in the end
            let width = precision as usize;
            write!(f, "{}{:0width$}", piconero, 0, width = width)?;
        }
        Ordering::Less => {
            // need to inject a comma in the number
            let nb_decimals = precision.abs() as usize;
            let real = format!("{:0width$}", piconero, width = nb_decimals);
            if real.len() == nb_decimals {
                write!(f, "0.{}", &real[real.len() - nb_decimals..])?;
            } else {
                write!(
                    f,
                    "{}.{}",
                    &real[0..(real.len() - nb_decimals)],
                    &real[real.len() - nb_decimals..]
                )?;
            }
        }
        Ordering::Equal => write!(f, "{}", piconero)?,
    }
    Ok(())
}

/// Represent an unsigned quantity of Monero, internally as piconero.
///
/// The [`Amount`] type can be used to express Monero amounts that supports arithmetic and
/// conversion to various denominations.
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(u64);

impl Amount {
    /// The zero amount.
    pub const ZERO: Amount = Amount(0);
    /// Exactly one piconero.
    pub const ONE_PICO: Amount = Amount(1);
    /// Exactly one monero.
    pub const ONE_XMR: Amount = Amount(1_000_000_000_000);

    /// Create an [`Amount`] with piconero precision and the given number of piconero.
    pub fn from_pico(piconero: u64) -> Amount {
        Amount(piconero)
    }

    /// Get the number of piconeros in this [`Amount`].
    pub fn as_pico(self) -> u64 {
        self.0
    }

    /// The maximum value of an [`Amount`].
    pub fn max_value() -> Amount {
        Amount(u64::max_value())
    }

    /// The minimum value of an [`Amount`].
    pub fn min_value() -> Amount {
        Amount(u64::min_value())
    }

    /// Convert from a value expressing moneros to an [`Amount`].
    pub fn from_xmr(xmr: f64) -> Result<Amount, ParsingError> {
        Amount::from_float_in(xmr, Denomination::Monero)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string. If you want to parse a value with denomination,
    /// use [`FromStr`].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, ParsingError> {
        let (negative, piconero) = parse_signed_to_piconero(s, denom)?;
        if negative {
            return Err(ParsingError::Negative);
        }
        if piconero > i64::max_value() as u64 {
            return Err(ParsingError::TooBig);
        }
        Ok(Amount::from_pico(piconero))
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// `to_string_with_denomination` or with [`fmt::Display`]. If you want to parse only the
    /// amount without the denomination, use `from_str_in`.
    pub fn from_str_with_denomination(s: &str) -> Result<Amount, ParsingError> {
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParsingError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParsingError::InvalidFormat);
        }

        Amount::from_str_in(amt_str, denom_str.parse()?)
    }

    /// Express this [`Amount`] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [`Amount`] as a floating-point value in Monero.
    ///
    /// Equivalent to `to_float_in(Denomination::Monero)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_xmr(self) -> f64 {
        self.to_float_in(Denomination::Monero)
    }

    /// Convert this [`Amount`] in floating-point notation with a given denomination. Can return
    /// error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<Amount, ParsingError> {
        if value < 0.0 {
            return Err(ParsingError::Negative);
        }
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        Amount::from_str_in(&value.to_string(), denom)
    }

    /// Format the value of this [`Amount`] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        fmt_piconero_in(self.as_pico(), false, f, denom)
    }

    /// Get a string number of this [`Amount`] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this [`Amount`] in the given denomination, suffixed with the
    /// abbreviation for the denomination.
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    // Some arithmetic that doesn't fit in `std::ops` traits.

    /// Checked addition.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_add(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_add(rhs.0).map(Amount)
    }

    /// Checked subtraction.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_sub(self, rhs: Amount) -> Option<Amount> {
        self.0.checked_sub(rhs.0).map(Amount)
    }

    /// Checked multiplication.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_mul(self, rhs: u64) -> Option<Amount> {
        self.0.checked_mul(rhs).map(Amount)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_div(self, rhs: u64) -> Option<Amount> {
        self.0.checked_div(rhs).map(Amount)
    }

    /// Checked remainder.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_rem(self, rhs: u64) -> Option<Amount> {
        self.0.checked_rem(rhs).map(Amount)
    }

    /// Convert to a signed amount.
    pub fn to_signed(self) -> Result<SignedAmount, ParsingError> {
        if self.as_pico() > SignedAmount::max_value().as_pico() as u64 {
            Err(ParsingError::TooBig)
        } else {
            Ok(SignedAmount::from_pico(self.as_pico() as i64))
        }
    }
}

impl default::Default for Amount {
    fn default() -> Self {
        Amount::ZERO
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Amount({:.12} XMR)", self.as_xmr())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Monero denominated string.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::Monero)?;
        write!(f, " {}", Denomination::Monero)
    }
}

impl ops::Add for Amount {
    type Output = Amount;

    fn add(self, rhs: Amount) -> Self::Output {
        self.checked_add(rhs).expect("Amount addition error")
    }
}

impl ops::AddAssign for Amount {
    fn add_assign(&mut self, other: Amount) {
        *self = *self + other
    }
}

impl ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, rhs: Amount) -> Self::Output {
        self.checked_sub(rhs).expect("Amount subtraction error")
    }
}

impl ops::SubAssign for Amount {
    fn sub_assign(&mut self, other: Amount) {
        *self = *self - other
    }
}

impl ops::Rem<u64> for Amount {
    type Output = Amount;

    fn rem(self, modulus: u64) -> Self {
        self.checked_rem(modulus).expect("Amount remainder error")
    }
}

impl ops::RemAssign<u64> for Amount {
    fn rem_assign(&mut self, modulus: u64) {
        *self = *self % modulus
    }
}

impl ops::Mul<u64> for Amount {
    type Output = Amount;

    fn mul(self, rhs: u64) -> Self::Output {
        self.checked_mul(rhs).expect("Amount multiplication error")
    }
}

impl ops::MulAssign<u64> for Amount {
    fn mul_assign(&mut self, rhs: u64) {
        *self = *self * rhs
    }
}

impl ops::Div<u64> for Amount {
    type Output = Amount;

    fn div(self, rhs: u64) -> Self::Output {
        self.checked_div(rhs).expect("Amount division error")
    }
}

impl ops::DivAssign<u64> for Amount {
    fn div_assign(&mut self, rhs: u64) {
        *self = *self / rhs
    }
}

impl FromStr for Amount {
    type Err = ParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::from_str_with_denomination(s)
    }
}

/// Represent an signed quantity of Monero, internally as signed monero.
///
/// The [`SignedAmount`] type can be used to express Monero amounts that supports arithmetic and
/// conversion to various denominations.
///
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignedAmount(i64);

impl SignedAmount {
    /// The zero amount.
    pub const ZERO: SignedAmount = SignedAmount(0);
    /// Exactly one piconero.
    pub const ONE_PICO: SignedAmount = SignedAmount(1);
    /// Exactly one monero.
    pub const ONE_XMR: SignedAmount = SignedAmount(1_000_000_000_000);

    /// Create an [`SignedAmount`] with piconero precision and the given number of piconeros.
    pub fn from_pico(piconero: i64) -> SignedAmount {
        SignedAmount(piconero)
    }

    /// Get the number of piconeros in this [`SignedAmount`].
    pub fn as_pico(self) -> i64 {
        self.0
    }

    /// The maximum value of an [`SignedAmount`].
    pub fn max_value() -> SignedAmount {
        SignedAmount(i64::max_value())
    }

    /// The minimum value of an [`SignedAmount`].
    pub fn min_value() -> SignedAmount {
        SignedAmount(i64::min_value())
    }

    /// Convert from a value expressing moneros to an [`SignedAmount`].
    pub fn from_xmr(xmr: f64) -> Result<SignedAmount, ParsingError> {
        SignedAmount::from_float_in(xmr, Denomination::Monero)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value with denomination,
    /// use [`FromStr`].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<SignedAmount, ParsingError> {
        let (negative, piconero) = parse_signed_to_piconero(s, denom)?;
        if piconero > i64::max_value() as u64 {
            return Err(ParsingError::TooBig);
        }
        Ok(match negative {
            true => SignedAmount(-(piconero as i64)),
            false => SignedAmount(piconero as i64),
        })
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// `to_string_with_denomination` or with [`fmt::Display`].
    ///
    /// If you want to parse only the amount without the denomination, use `from_str_in`.
    pub fn from_str_with_denomination(s: &str) -> Result<SignedAmount, ParsingError> {
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().unwrap();
        let denom_str = split.next().ok_or(ParsingError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(ParsingError::InvalidFormat);
        }

        SignedAmount::from_str_in(amt_str, denom_str.parse()?)
    }

    /// Express this [`SignedAmount`] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> f64 {
        f64::from_str(&self.to_string_in(denom)).unwrap()
    }

    /// Express this [`SignedAmount`] as a floating-point value in Monero.
    ///
    /// Equivalent to `to_float_in(Denomination::Monero)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_xmr(self) -> f64 {
        self.to_float_in(Denomination::Monero)
    }

    /// Convert this [`SignedAmount`] in floating-point notation with a given denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<SignedAmount, ParsingError> {
        // This is inefficient, but the safest way to deal with this. The parsing logic is safe.
        // Any performance-critical application should not be dealing with floats.
        SignedAmount::from_str_in(&value.to_string(), denom)
    }

    /// Format the value of this [`SignedAmount`] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn fmt_value_in(self, f: &mut dyn fmt::Write, denom: Denomination) -> fmt::Result {
        let picos = self
            .as_pico()
            .checked_abs()
            .map(|a: i64| a as u64)
            .unwrap_or_else(|| {
                // We could also hard code this into `9223372036854775808`
                u64::max_value() - self.as_pico() as u64 + 1
            });
        fmt_piconero_in(picos, self.is_negative(), f, denom)
    }

    /// Get a string number of this [`SignedAmount`] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        buf
    }

    /// Get a formatted string of this [`SignedAmount`] in the given denomination, suffixed with
    /// the abbreviation for the denomination.
    pub fn to_string_with_denomination(self, denom: Denomination) -> String {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom).unwrap();
        write!(buf, " {}", denom).unwrap();
        buf
    }

    // Some arithmetic that doesn't fit in `std::ops` traits.

    /// Get the absolute value of this [`SignedAmount`].
    pub fn abs(self) -> SignedAmount {
        SignedAmount(self.0.abs())
    }

    /// Returns a number representing sign of this [`SignedAmount`].
    ///
    /// - `0` if the amount is zero
    /// - `1` if the amount is positive
    /// - `-1` if the amount is negative
    pub fn signum(self) -> i64 {
        self.0.signum()
    }

    /// Returns `true` if this [`SignedAmount`] is positive and `false` if this [`SignedAmount`] is
    /// zero or negative.
    pub fn is_positive(self) -> bool {
        self.0.is_positive()
    }

    /// Returns `true` if this [`SignedAmount`] is negative and `false` if this [`SignedAmount`] is
    /// zero or positive.
    pub fn is_negative(self) -> bool {
        self.0.is_negative()
    }

    /// Get the absolute value of this [`SignedAmount`].  Returns [`None`] if overflow occurred.
    /// (`self == min_value()`)
    pub fn checked_abs(self) -> Option<SignedAmount> {
        self.0.checked_abs().map(SignedAmount)
    }

    /// Checked addition.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_add(self, rhs: SignedAmount) -> Option<SignedAmount> {
        self.0.checked_add(rhs.0).map(SignedAmount)
    }

    /// Checked subtraction.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        self.0.checked_sub(rhs.0).map(SignedAmount)
    }

    /// Checked multiplication.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_mul(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_mul(rhs).map(SignedAmount)
    }

    /// Checked integer division.
    /// Be aware that integer division loses the remainder if no exact division
    /// can be made.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_div(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_div(rhs).map(SignedAmount)
    }

    /// Checked remainder.
    /// Returns [`None`] if overflow occurred.
    pub fn checked_rem(self, rhs: i64) -> Option<SignedAmount> {
        self.0.checked_rem(rhs).map(SignedAmount)
    }

    /// Subtraction that doesn't allow negative [`SignedAmount`]s.
    /// Returns [`None`] if either `self`, `rhs` or the result is strictly negative.
    pub fn positive_sub(self, rhs: SignedAmount) -> Option<SignedAmount> {
        if self.is_negative() || rhs.is_negative() || rhs > self {
            None
        } else {
            self.checked_sub(rhs)
        }
    }

    /// Convert to an unsigned amount.
    pub fn to_unsigned(self) -> Result<Amount, ParsingError> {
        if self.is_negative() {
            Err(ParsingError::Negative)
        } else {
            Ok(Amount::from_pico(self.as_pico() as u64))
        }
    }
}

impl default::Default for SignedAmount {
    fn default() -> Self {
        SignedAmount::ZERO
    }
}

impl fmt::Debug for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignedAmount({:.12} XMR)", self.as_xmr())
    }
}

// No one should depend on a binding contract for Display for this type.
// Just using Monero denominated string.
impl fmt::Display for SignedAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_value_in(f, Denomination::Monero)?;
        write!(f, " {}", Denomination::Monero)
    }
}

impl ops::Add for SignedAmount {
    type Output = SignedAmount;

    fn add(self, rhs: SignedAmount) -> Self::Output {
        self.checked_add(rhs).expect("SignedAmount addition error")
    }
}

impl ops::AddAssign for SignedAmount {
    fn add_assign(&mut self, other: SignedAmount) {
        *self = *self + other
    }
}

impl ops::Sub for SignedAmount {
    type Output = SignedAmount;

    fn sub(self, rhs: SignedAmount) -> Self::Output {
        self.checked_sub(rhs)
            .expect("SignedAmount subtraction error")
    }
}

impl ops::SubAssign for SignedAmount {
    fn sub_assign(&mut self, other: SignedAmount) {
        *self = *self - other
    }
}

impl ops::Rem<i64> for SignedAmount {
    type Output = SignedAmount;

    fn rem(self, modulus: i64) -> Self {
        self.checked_rem(modulus)
            .expect("SignedAmount remainder error")
    }
}

impl ops::RemAssign<i64> for SignedAmount {
    fn rem_assign(&mut self, modulus: i64) {
        *self = *self % modulus
    }
}

impl ops::Mul<i64> for SignedAmount {
    type Output = SignedAmount;

    fn mul(self, rhs: i64) -> Self::Output {
        self.checked_mul(rhs)
            .expect("SignedAmount multiplication error")
    }
}

impl ops::MulAssign<i64> for SignedAmount {
    fn mul_assign(&mut self, rhs: i64) {
        *self = *self * rhs
    }
}

impl ops::Div<i64> for SignedAmount {
    type Output = SignedAmount;

    fn div(self, rhs: i64) -> Self::Output {
        self.checked_div(rhs).expect("SignedAmount division error")
    }
}

impl ops::DivAssign<i64> for SignedAmount {
    fn div_assign(&mut self, rhs: i64) {
        *self = *self / rhs
    }
}

impl FromStr for SignedAmount {
    type Err = ParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SignedAmount::from_str_with_denomination(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::str::FromStr;

    #[test]
    fn add_sub_mul_div() {
        let pico = Amount::from_pico;
        let spico = SignedAmount::from_pico;

        assert_eq!(pico(15) + pico(15), pico(30));
        assert_eq!(pico(15) - pico(15), pico(0));
        assert_eq!(pico(14) * 3, pico(42));
        assert_eq!(pico(14) / 2, pico(7));
        assert_eq!(pico(14) % 3, pico(2));
        assert_eq!(spico(15) - spico(20), spico(-5));
        assert_eq!(spico(-14) * 3, spico(-42));
        assert_eq!(spico(-14) / 2, spico(-7));
        assert_eq!(spico(-14) % 3, spico(-2));

        let mut b = spico(-5);
        b += spico(13);
        assert_eq!(b, spico(8));
        b -= spico(3);
        assert_eq!(b, spico(5));
        b *= 6;
        assert_eq!(b, spico(30));
        b /= 3;
        assert_eq!(b, spico(10));
        b %= 3;
        assert_eq!(b, spico(1));

        // panic on overflow
        let result = panic::catch_unwind(|| Amount::max_value() + Amount::from_pico(1));
        assert!(result.is_err());
        let result = panic::catch_unwind(|| Amount::from_pico(8446744073709551615) * 3);
        assert!(result.is_err());
    }

    #[test]
    fn checked_arithmetic() {
        let pico = Amount::from_pico;
        let spico = SignedAmount::from_pico;

        assert_eq!(pico(42).checked_add(pico(1)), Some(pico(43)));
        assert_eq!(SignedAmount::max_value().checked_add(spico(1)), None);
        assert_eq!(SignedAmount::min_value().checked_sub(spico(1)), None);
        assert_eq!(Amount::max_value().checked_add(pico(1)), None);
        assert_eq!(Amount::min_value().checked_sub(pico(1)), None);

        assert_eq!(pico(5).checked_sub(pico(3)), Some(pico(2)));
        assert_eq!(pico(5).checked_sub(pico(6)), None);
        assert_eq!(spico(5).checked_sub(spico(6)), Some(spico(-1)));
        assert_eq!(pico(5).checked_rem(2), Some(pico(1)));

        assert_eq!(pico(5).checked_div(2), Some(pico(2))); // integer division
        assert_eq!(spico(-6).checked_div(2), Some(spico(-3)));

        assert_eq!(spico(-5).positive_sub(spico(3)), None);
        assert_eq!(spico(5).positive_sub(spico(-3)), None);
        assert_eq!(spico(3).positive_sub(spico(5)), None);
        assert_eq!(spico(3).positive_sub(spico(3)), Some(spico(0)));
        assert_eq!(spico(5).positive_sub(spico(3)), Some(spico(2)));
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn floating_point() {
        use super::Denomination as D;
        let f = Amount::from_float_in;
        let sf = SignedAmount::from_float_in;
        let pico = Amount::from_pico;
        let spico = SignedAmount::from_pico;

        assert_eq!(f(11.22, D::Monero), Ok(pico(11220000000000)));
        assert_eq!(sf(-11.22, D::Millinero), Ok(spico(-11220000000)));
        assert_eq!(f(11.22, D::Micronero), Ok(pico(11220000)));
        assert_eq!(f(0.0001234, D::Monero), Ok(pico(123400000)));
        assert_eq!(sf(-0.00012345, D::Monero), Ok(spico(-123450000)));

        assert_eq!(f(-100.0, D::Piconero), Err(ParsingError::Negative));
        assert_eq!(f(11.22, D::Piconero), Err(ParsingError::TooPrecise));
        assert_eq!(sf(-0.1, D::Piconero), Err(ParsingError::TooPrecise));
        assert_eq!(
            f(42.000_000_000_000_1, D::Monero),
            Err(ParsingError::TooPrecise)
        );
        assert_eq!(sf(-184467440738.0, D::Monero), Err(ParsingError::TooBig));
        assert_eq!(
            f(18446744073709551617.0, D::Piconero),
            Err(ParsingError::TooBig)
        );
        assert_eq!(
            f(
                SignedAmount::max_value().to_float_in(D::Piconero) + 1.0,
                D::Piconero
            ),
            Err(ParsingError::TooBig)
        );
        assert_eq!(
            f(
                Amount::max_value().to_float_in(D::Piconero) + 1.0,
                D::Piconero
            ),
            Err(ParsingError::TooBig)
        );

        let xmr = move |f| SignedAmount::from_xmr(f).unwrap();
        assert_eq!(xmr(2.5).to_float_in(D::Monero), 2.5);
        assert_eq!(xmr(-2.5).to_float_in(D::Millinero), -2500.0);
        assert_eq!(xmr(-2.5).to_float_in(D::Micronero), -2500000.0);
        assert_eq!(xmr(-2.5).to_float_in(D::Nanonero), -2500000000.0);
        assert_eq!(xmr(2.5).to_float_in(D::Piconero), 2500000000000.0);

        let xmr = move |f| Amount::from_xmr(f).unwrap();
        assert_eq!(&xmr(0.0012).to_float_in(D::Monero).to_string(), "0.0012")
    }

    #[test]
    fn parsing() {
        use super::ParsingError as E;
        let xmr = Denomination::Monero;
        let pico = Denomination::Piconero;
        let p = Amount::from_str_in;
        let sp = SignedAmount::from_str_in;

        assert_eq!(p("x", xmr), Err(E::InvalidCharacter('x')));
        assert_eq!(p("-", xmr), Err(E::InvalidFormat));
        assert_eq!(sp("-", xmr), Err(E::InvalidFormat));
        assert_eq!(p("-1.0x", xmr), Err(E::InvalidCharacter('x')));
        assert_eq!(p("0.0 ", xmr), Err(ParsingError::InvalidCharacter(' ')));
        assert_eq!(p("0.000.000", xmr), Err(E::InvalidFormat));
        let more_than_max = format!("1{}", Amount::max_value());
        assert_eq!(p(&more_than_max, xmr), Err(E::TooBig));
        assert_eq!(p("0.0000000000042", xmr), Err(E::TooPrecise));

        assert_eq!(p("1", xmr), Ok(Amount::from_pico(1_000_000_000_000)));
        assert_eq!(
            sp("-.5", xmr),
            Ok(SignedAmount::from_pico(-500_000_000_000))
        );
        assert_eq!(p("1.1", xmr), Ok(Amount::from_pico(1_100_000_000_000)));
        assert_eq!(p("100", pico), Ok(Amount::from_pico(100)));
        assert_eq!(p("55", pico), Ok(Amount::from_pico(55)));
        assert_eq!(
            p("5500000000000000000", pico),
            Ok(Amount::from_pico(5_500_000_000_000_000_000))
        );
        // Should this even pass?
        assert_eq!(
            p("5500000000000000000.", pico),
            Ok(Amount::from_pico(5_500_000_000_000_000_000))
        );
        assert_eq!(
            p("1234567.123456789123", xmr),
            Ok(Amount::from_pico(1_234_567_123_456_789_123))
        );

        // make sure Piconero > i64::max_value() is checked.
        let amount = Amount::from_pico(i64::max_value() as u64);
        assert_eq!(
            Amount::from_str_in(&amount.to_string_in(pico), pico),
            Ok(amount)
        );
        assert_eq!(
            Amount::from_str_in(&(amount + Amount(1)).to_string_in(pico), pico),
            Err(E::TooBig)
        );

        // exactly 50 chars.
        assert_eq!(
            p(
                "100000000000000.0000000000000000000000000000000000",
                Denomination::Monero
            ),
            Err(E::TooBig)
        );
        // more than 50 chars.
        assert_eq!(
            p(
                "100000000000000.00000000000000000000000000000000000",
                Denomination::Monero
            ),
            Err(E::InputTooLarge)
        );
    }

    #[test]
    fn to_string() {
        use super::Denomination as D;

        assert_eq!(Amount::ONE_XMR.to_string_in(D::Monero), "1.000000000000");
        assert_eq!(Amount::ONE_XMR.to_string_in(D::Piconero), "1000000000000");
        assert_eq!(Amount::ONE_PICO.to_string_in(D::Monero), "0.000000000001");
        assert_eq!(
            SignedAmount::from_pico(-42).to_string_in(D::Monero),
            "-0.000000000042"
        );

        assert_eq!(
            Amount::ONE_XMR.to_string_with_denomination(D::Monero),
            "1.000000000000 XMR"
        );
        assert_eq!(
            SignedAmount::ONE_XMR.to_string_with_denomination(D::Piconero),
            "1000000000000 piconero"
        );
        assert_eq!(
            Amount::ONE_PICO.to_string_with_denomination(D::Monero),
            "0.000000000001 XMR"
        );
        assert_eq!(
            SignedAmount::from_pico(-42).to_string_with_denomination(D::Monero),
            "-0.000000000042 XMR"
        );
    }

    #[test]
    fn test_unsigned_signed_conversion() {
        use super::ParsingError as E;
        let p = Amount::from_pico;
        let sp = SignedAmount::from_pico;

        assert_eq!(Amount::max_value().to_signed(), Err(E::TooBig));
        assert_eq!(
            p(i64::max_value() as u64).to_signed(),
            Ok(sp(i64::max_value()))
        );
        assert_eq!(p(0).to_signed(), Ok(sp(0)));
        assert_eq!(p(1).to_signed(), Ok(sp(1)));
        assert_eq!(p(1).to_signed(), Ok(sp(1)));
        assert_eq!(p(i64::max_value() as u64 + 1).to_signed(), Err(E::TooBig));

        assert_eq!(sp(-1).to_unsigned(), Err(E::Negative));
        assert_eq!(
            sp(i64::max_value()).to_unsigned(),
            Ok(p(i64::max_value() as u64))
        );

        assert_eq!(sp(0).to_unsigned().unwrap().to_signed(), Ok(sp(0)));
        assert_eq!(sp(1).to_unsigned().unwrap().to_signed(), Ok(sp(1)));
        assert_eq!(
            sp(i64::max_value()).to_unsigned().unwrap().to_signed(),
            Ok(sp(i64::max_value()))
        );
    }

    #[test]
    fn from_str() {
        use super::ParsingError as E;
        let p = Amount::from_str;
        let sp = SignedAmount::from_str;

        assert_eq!(p("x XMR"), Err(E::InvalidCharacter('x')));
        assert_eq!(p("5 XMR XMR"), Err(E::InvalidFormat));
        assert_eq!(p("5 5 XMR"), Err(E::InvalidFormat));

        assert_eq!(p("5 BCH"), Err(E::UnknownDenomination("BCH".to_owned())));

        assert_eq!(p("-1 XMR"), Err(E::Negative));
        assert_eq!(p("-0.0 XMR"), Err(E::Negative));
        assert_eq!(p("0.1234567891234 XMR"), Err(E::TooPrecise));
        assert_eq!(sp("-0.1 piconero"), Err(E::TooPrecise));
        assert_eq!(p("0.1234567 micronero"), Err(E::TooPrecise));
        assert_eq!(sp("-1.0001 nanonero"), Err(E::TooPrecise));
        assert_eq!(sp("-200000000000 XMR"), Err(E::TooBig));
        assert_eq!(p("18446744073709551616 piconero"), Err(E::TooBig));

        assert_eq!(p(".5 nanonero"), Ok(Amount::from_pico(500)));
        assert_eq!(sp("-.5 nanonero"), Ok(SignedAmount::from_pico(-500)));
        assert_eq!(p("0.000000253583 XMR"), Ok(Amount::from_pico(253583)));
        assert_eq!(sp("-5 piconero"), Ok(SignedAmount::from_pico(-5)));
        assert_eq!(
            p("0.100000000000 XMR"),
            Ok(Amount::from_pico(100_000_000_000))
        );
        assert_eq!(sp("-10 nanonero"), Ok(SignedAmount::from_pico(-10_000)));
        assert_eq!(
            sp("-10 micronero"),
            Ok(SignedAmount::from_pico(-10_000_000))
        );
        assert_eq!(
            sp("-10 millinero"),
            Ok(SignedAmount::from_pico(-10_000_000_000))
        );
    }

    #[test]
    fn to_from_string_in() {
        use super::Denomination as D;
        let ua_str = Amount::from_str_in;
        let ua_sat = Amount::from_pico;
        let sa_str = SignedAmount::from_str_in;
        let sa_sat = SignedAmount::from_pico;

        assert_eq!("0.500", Amount::from_pico(500).to_string_in(D::Nanonero));
        assert_eq!(
            "-0.500",
            SignedAmount::from_pico(-500).to_string_in(D::Nanonero)
        );
        assert_eq!(
            "0.002535830000",
            Amount::from_pico(2535830000).to_string_in(D::Monero)
        );
        assert_eq!("-5", SignedAmount::from_pico(-5).to_string_in(D::Piconero));
        assert_eq!(
            "0.100000000000",
            Amount::from_pico(100_000_000_000).to_string_in(D::Monero)
        );
        assert_eq!(
            "-10.000",
            SignedAmount::from_pico(-10_000).to_string_in(D::Nanonero)
        );

        assert_eq!(
            ua_str(&ua_sat(0).to_string_in(D::Piconero), D::Piconero),
            Ok(ua_sat(0))
        );
        assert_eq!(
            ua_str(&ua_sat(500).to_string_in(D::Monero), D::Monero),
            Ok(ua_sat(500))
        );
        assert_eq!(
            ua_str(&ua_sat(21_000_000).to_string_in(D::Nanonero), D::Nanonero),
            Ok(ua_sat(21_000_000))
        );
        assert_eq!(
            ua_str(&ua_sat(1).to_string_in(D::Micronero), D::Micronero),
            Ok(ua_sat(1))
        );
        assert_eq!(
            ua_str(
                &ua_sat(1_000_000_000_000).to_string_in(D::Millinero),
                D::Millinero
            ),
            Ok(ua_sat(1_000_000_000_000))
        );
        assert_eq!(
            ua_str(
                &ua_sat(u64::max_value()).to_string_in(D::Millinero),
                D::Millinero
            ),
            Err(ParsingError::TooBig)
        );

        assert_eq!(
            sa_str(&sa_sat(-1).to_string_in(D::Micronero), D::Micronero),
            Ok(sa_sat(-1))
        );

        assert_eq!(
            sa_str(
                &sa_sat(i64::max_value()).to_string_in(D::Piconero),
                D::Micronero
            ),
            Err(ParsingError::TooBig)
        );
        // Test an overflow bug in `abs()`
        assert_eq!(
            sa_str(
                &sa_sat(i64::min_value()).to_string_in(D::Piconero),
                D::Micronero
            ),
            Err(ParsingError::TooBig)
        );
    }

    #[test]
    fn to_string_with_denomination_from_str_roundtrip() {
        use super::Denomination as D;
        let amt = Amount::from_pico(42);
        let denom = Amount::to_string_with_denomination;
        assert_eq!(Amount::from_str(&denom(amt, D::Monero)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::Millinero)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::Micronero)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::Nanonero)), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::Piconero)), Ok(amt));

        assert_eq!(
            Amount::from_str("42 piconero XMR"),
            Err(ParsingError::InvalidFormat)
        );
        assert_eq!(
            SignedAmount::from_str("-42 piconero XMR"),
            Err(ParsingError::InvalidFormat)
        );
    }
}
