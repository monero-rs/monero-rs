// Rust Monero Library
// Written in 2021-2023 by
//   Monero Rust Contributors
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

/// A set of denominations in which amounts can be expressed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Denomination {
    /// xmr
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
            Denomination::Monero => "xmr",
            Denomination::Millinero => "millinero",
            Denomination::Micronero => "micronero",
            Denomination::Nanonero => "nanonero",
            Denomination::Piconero => "piconero",
        })
    }
}

impl FromStr for Denomination {
    type Err = AmountParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "xmr" | "XMR" | "monero" => Ok(Denomination::Monero),
            "millinero" | "mXMR" => Ok(Denomination::Millinero),
            "micronero" | "µXMR" | "mcXMR" => Ok(Denomination::Micronero),
            "nanonero" | "nXMR" => Ok(Denomination::Nanonero),
            "piconero" | "pXMR" => Ok(Denomination::Piconero),
            d => Err(AmountParsingError::UnknownDenomination(d.to_owned())),
        }
    }
}

/// An error during amount parsing.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum AmountParsingError {
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
fn parse_signed_to_piconero(
    mut s: &str,
    denom: Denomination,
) -> Result<(bool, u64), AmountParsingError> {
    if s.is_empty() {
        return Err(AmountParsingError::InvalidFormat);
    }
    if s.len() > 50 {
        return Err(AmountParsingError::InputTooLarge);
    }

    let is_negative = s.starts_with('-');
    if is_negative {
        if s.len() == 1 {
            return Err(AmountParsingError::InvalidFormat);
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
            let last_n = precision_diff.unsigned_abs() as usize;
            if is_too_precise(s, last_n) {
                return Err(AmountParsingError::TooPrecise);
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
                    None => return Err(AmountParsingError::TooBig),
                    Some(val) => match val.checked_add((c as u8 - b'0') as u64) {
                        None => return Err(AmountParsingError::TooBig),
                        Some(val) => value = val,
                    },
                }
                // Increment the decimal digit counter if past decimal.
                decimals = match decimals {
                    None => None,
                    Some(d) if d < max_decimals => Some(d + 1),
                    _ => return Err(AmountParsingError::TooPrecise),
                };
            }
            '.' => match decimals {
                None => decimals = Some(0),
                // Double decimal dot.
                _ => return Err(AmountParsingError::InvalidFormat),
            },
            c => return Err(AmountParsingError::InvalidCharacter(c)),
        }
    }

    // Decimally shift left by `max_decimals - decimals`.
    let scale_factor = max_decimals - decimals.unwrap_or(0);
    for _ in 0..scale_factor {
        value = match 10_u64.checked_mul(value) {
            Some(v) => v,
            None => return Err(AmountParsingError::TooBig),
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
            let nb_decimals = precision.unsigned_abs() as usize;
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
        Amount(u64::MAX)
    }

    /// The minimum value of an [`Amount`].
    pub fn min_value() -> Amount {
        Amount(u64::MIN)
    }

    /// Convert from a value expressing moneros to an [`Amount`].
    pub fn from_xmr(xmr: f64) -> Result<Amount, AmountParsingError> {
        Amount::from_float_in(xmr, Denomination::Monero)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string. If you want to parse a value with denomination,
    /// use [`FromStr`].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<Amount, AmountParsingError> {
        let (negative, piconero) = parse_signed_to_piconero(s, denom)?;
        if negative {
            return Err(AmountParsingError::Negative);
        }
        if piconero > i64::MAX as u64 {
            return Err(AmountParsingError::TooBig);
        }
        Ok(Amount::from_pico(piconero))
    }

    /// Parses amounts with denomination suffix like they are produced with
    /// `to_string_with_denomination` or with [`fmt::Display`]. If you want to parse only the
    /// amount without the denomination, use `from_str_in`.
    pub fn from_str_with_denomination(s: &str) -> Result<Amount, AmountParsingError> {
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().ok_or(AmountParsingError::InvalidFormat)?;
        let denom_str = split.next().ok_or(AmountParsingError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(AmountParsingError::InvalidFormat);
        }

        Amount::from_str_in(amt_str, denom_str.parse()?)
    }

    /// Express this [`Amount`] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> Result<f64, AmountParsingError> {
        f64::from_str(&self.to_string_in(denom)?)
            .map_err(|e| AmountParsingError::UnknownDenomination(e.to_string()))
    }

    /// Express this [`Amount`] as a floating-point value in Monero.
    ///
    /// Equivalent to `to_float_in(Denomination::Monero)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_xmr(self) -> Result<f64, AmountParsingError> {
        self.to_float_in(Denomination::Monero)
            .map_err(|e| AmountParsingError::UnknownDenomination(e.to_string()))
    }

    /// Convert this [`Amount`] in floating-point notation with a given denomination. Can return
    /// error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(value: f64, denom: Denomination) -> Result<Amount, AmountParsingError> {
        if value < 0.0 {
            return Err(AmountParsingError::Negative);
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
    pub fn to_string_in(self, denom: Denomination) -> Result<String, AmountParsingError> {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom)
            .map_err(|_| AmountParsingError::InvalidFormat)?;
        Ok(buf)
    }

    /// Get a formatted string of this [`Amount`] in the given denomination, suffixed with the
    /// abbreviation for the denomination.
    pub fn to_string_with_denomination(
        self,
        denom: Denomination,
    ) -> Result<String, AmountParsingError> {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom)
            .map_err(|_| AmountParsingError::InvalidFormat)?;
        write!(buf, " {}", denom).map_err(|_| AmountParsingError::InvalidFormat)?;
        Ok(buf)
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
    pub fn to_signed(self) -> Result<SignedAmount, AmountParsingError> {
        if self.as_pico() > SignedAmount::max_value().as_pico() as u64 {
            Err(AmountParsingError::TooBig)
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
        write!(
            f,
            "Amount({:.12} xmr)",
            self.as_xmr().map_err(|_| fmt::Error)?
        )
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
    type Err = AmountParsingError;

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
        SignedAmount(i64::MAX)
    }

    /// The minimum value of an [`SignedAmount`].
    pub fn min_value() -> SignedAmount {
        SignedAmount(i64::MIN)
    }

    /// Convert from a value expressing moneros to an [`SignedAmount`].
    pub fn from_xmr(xmr: f64) -> Result<SignedAmount, AmountParsingError> {
        SignedAmount::from_float_in(xmr, Denomination::Monero)
    }

    /// Parse a decimal string as a value in the given denomination.
    ///
    /// Note: This only parses the value string.  If you want to parse a value with denomination,
    /// use [`FromStr`].
    pub fn from_str_in(s: &str, denom: Denomination) -> Result<SignedAmount, AmountParsingError> {
        let (negative, piconero) = parse_signed_to_piconero(s, denom)?;
        if piconero > i64::MAX as u64 {
            return Err(AmountParsingError::TooBig);
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
    pub fn from_str_with_denomination(s: &str) -> Result<SignedAmount, AmountParsingError> {
        let mut split = s.splitn(3, ' ');
        let amt_str = split.next().ok_or(AmountParsingError::InvalidFormat)?;
        let denom_str = split.next().ok_or(AmountParsingError::InvalidFormat)?;
        if split.next().is_some() {
            return Err(AmountParsingError::InvalidFormat);
        }

        SignedAmount::from_str_in(amt_str, denom_str.parse()?)
    }

    /// Express this [`SignedAmount`] as a floating-point value in the given denomination.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn to_float_in(self, denom: Denomination) -> Result<f64, AmountParsingError> {
        f64::from_str(&self.to_string_in(denom)?)
            .map_err(|e| AmountParsingError::UnknownDenomination(e.to_string()))
    }

    /// Express this [`SignedAmount`] as a floating-point value in Monero.
    ///
    /// Equivalent to `to_float_in(Denomination::Monero)`.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn as_xmr(self) -> Result<f64, AmountParsingError> {
        self.to_float_in(Denomination::Monero)
    }

    /// Convert this [`SignedAmount`] in floating-point notation with a given denomination.
    /// Can return error if the amount is too big, too precise or negative.
    ///
    /// Please be aware of the risk of using floating-point numbers.
    pub fn from_float_in(
        value: f64,
        denom: Denomination,
    ) -> Result<SignedAmount, AmountParsingError> {
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
                u64::MAX - self.as_pico() as u64 + 1
            });
        fmt_piconero_in(picos, self.is_negative(), f, denom)
    }

    /// Get a string number of this [`SignedAmount`] in the given denomination.
    ///
    /// Does not include the denomination.
    pub fn to_string_in(self, denom: Denomination) -> Result<String, AmountParsingError> {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom)
            .map_err(|_| AmountParsingError::InvalidFormat)?;
        Ok(buf)
    }

    /// Get a formatted string of this [`SignedAmount`] in the given denomination, suffixed with
    /// the abbreviation for the denomination.
    pub fn to_string_with_denomination(
        self,
        denom: Denomination,
    ) -> Result<String, AmountParsingError> {
        let mut buf = String::new();
        self.fmt_value_in(&mut buf, denom)
            .map_err(|_| AmountParsingError::InvalidFormat)?;
        write!(buf, " {}", denom).map_err(|_| AmountParsingError::InvalidFormat)?;
        Ok(buf)
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
    pub fn to_unsigned(self) -> Result<Amount, AmountParsingError> {
        if self.is_negative() {
            Err(AmountParsingError::Negative)
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
        write!(
            f,
            "SignedAmount({:.12} xmr)",
            self.as_xmr().map_err(|_| fmt::Error)?
        )
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
    type Err = AmountParsingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SignedAmount::from_str_with_denomination(s)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub mod serde {
    //! This module adds serde serialization and deserialization support for Amounts.
    //! Since there is not a default way to serialize and deserialize Amounts, multiple
    //! ways are supported and it's up to the user to decide which serialiation to use.
    //! The provided modules can be used as follows:
    //!
    //! ```rust
    //! # use serde_crate::{Serialize, Deserialize};
    //! use monero::Amount;
    //!
    //! #[derive(Serialize, Deserialize)]
    //! # #[serde(crate = "serde_crate")]
    //! pub struct HasAmount {
    //!     #[serde(with = "monero::util::amount::serde::as_xmr")]
    //!     pub amount: Amount,
    //! }
    //! ```
    //!
    //! Notabene that due to the limits of floating point precission, ::as_xmr
    //! serializes amounts as strings.

    use super::{Amount, Denomination, SignedAmount};
    use sealed::sealed;
    use serde_crate::ser::Error;
    use serde_crate::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

    #[sealed]
    /// This trait is used only to avoid code duplication and naming collisions of the different
    /// serde serialization crates.
    pub trait SerdeAmount: Copy + Sized {
        /// Serialize with [`Serializer`] the amount as piconero.
        fn ser_pico<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        /// Deserialize with [`Deserializer`] an amount in piconero.
        fn des_pico<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
        /// Serialize with [`Serializer`] the amount as monero.
        fn ser_xmr<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        /// Deserialize with [`Deserializer`] an amount in monero.
        fn des_xmr<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error>;
    }

    #[sealed]
    /// This trait is only for internal Amount type serialization/deserialization.
    pub trait SerdeAmountForOpt: Copy + Sized + SerdeAmount {
        /// Return the type prefix (`i` or `u`) used to sign or not the amount.
        fn type_prefix() -> &'static str;
        /// Serialize with [`Serializer`] an optional amount as piconero.
        fn ser_pico_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
        /// Serialize with [`Serializer`] an optional amount as monero.
        fn ser_xmr_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error>;
    }

    #[sealed]
    /// This trait is for serialization of `&[Amount]` and `&[SignedAmount]` slices
    pub trait SerdeAmountForSlice: Copy + Sized + SerdeAmount {
        /// Return the type prefix (`i` or `u`) used to sign or not the amount.
        fn type_prefix() -> &'static str;
        /// Serialize with [`Serializer`] a slice of amounts as a slice of piconeros.
        fn ser_pico_slice<S: SerializeSeq>(&self, s: &mut S) -> Result<(), S::Error>;
        /// Serialize with [`Serializer`] a slice of amounts as a slice of moneros.
        fn ser_xmr_slice<S: SerializeSeq>(&self, s: &mut S) -> Result<(), S::Error>;
    }

    #[sealed]
    impl SerdeAmount for Amount {
        fn ser_pico<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            u64::serialize(&self.as_pico(), s)
        }
        fn des_pico<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(Amount::from_pico(u64::deserialize(d)?))
        }
        fn ser_xmr<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            String::serialize(
                &self
                    .to_string_in(Denomination::Monero)
                    .map_err(S::Error::custom)?,
                s,
            )
        }
        fn des_xmr<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde_crate::de::Error;
            Amount::from_str_in(&String::deserialize(d)?, Denomination::Monero)
                .map_err(D::Error::custom)
        }
    }

    #[sealed]
    impl SerdeAmountForOpt for Amount {
        fn type_prefix() -> &'static str {
            "u"
        }
        fn ser_pico_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.as_pico())
        }
        fn ser_xmr_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(
                &self
                    .to_string_in(Denomination::Monero)
                    .map_err(S::Error::custom)?,
            )
        }
    }

    #[sealed]
    impl SerdeAmountForSlice for Amount {
        fn type_prefix() -> &'static str {
            "u"
        }

        fn ser_pico_slice<S: SerializeSeq>(&self, s: &mut S) -> Result<(), S::Error> {
            s.serialize_element(&self.as_pico())
        }

        fn ser_xmr_slice<S: SerializeSeq>(&self, s: &mut S) -> Result<(), S::Error> {
            s.serialize_element(
                &self
                    .to_string_in(Denomination::Monero)
                    .map_err(S::Error::custom)?,
            )
        }
    }

    #[sealed]
    impl SerdeAmount for SignedAmount {
        fn ser_pico<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            i64::serialize(&self.as_pico(), s)
        }
        fn des_pico<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            Ok(SignedAmount::from_pico(i64::deserialize(d)?))
        }
        fn ser_xmr<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            String::serialize(
                &self
                    .to_string_in(Denomination::Monero)
                    .map_err(S::Error::custom)?,
                s,
            )
        }
        fn des_xmr<'d, D: Deserializer<'d>>(d: D) -> Result<Self, D::Error> {
            use serde_crate::de::Error;
            SignedAmount::from_str_in(&String::deserialize(d)?, Denomination::Monero)
                .map_err(D::Error::custom)
        }
    }

    #[sealed]
    impl SerdeAmountForOpt for SignedAmount {
        fn type_prefix() -> &'static str {
            "i"
        }
        fn ser_pico_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(&self.as_pico())
        }
        fn ser_xmr_opt<S: Serializer>(self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_some(
                &self
                    .to_string_in(Denomination::Monero)
                    .map_err(S::Error::custom)?,
            )
        }
    }

    #[sealed]
    impl SerdeAmountForSlice for SignedAmount {
        fn type_prefix() -> &'static str {
            "i"
        }

        fn ser_pico_slice<S: SerializeSeq>(&self, s: &mut S) -> Result<(), S::Error> {
            s.serialize_element(&self.as_pico())
        }

        fn ser_xmr_slice<S: SerializeSeq>(&self, s: &mut S) -> Result<(), S::Error> {
            s.serialize_element(
                &self
                    .to_string_in(Denomination::Monero)
                    .map_err(S::Error::custom)?,
            )
        }
    }

    pub mod as_pico {
        // methods are implementation of a standardized serde-specific signature
        #![allow(missing_docs)]

        //! Serialize and deserialize [`Amount`] as real numbers denominated in piconero.
        //! Use with `#[serde(with = "monero::util::amount::serde::as_pico")]`.
        //!
        //! [`Amount`]: crate::util::amount::Amount

        use super::SerdeAmount;
        use serde_crate::{Deserializer, Serializer};

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_pico(s)
        }
        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_pico(d)
        }

        pub mod opt {
            //! Serialize and deserialize [Option] as a number denominated in piconero.
            //! Use with `#[serde(default, with = "monero::util::amount::serde::as_pico::opt")]`.

            use super::super::SerdeAmountForOpt;
            use core::fmt;
            use core::marker::PhantomData;
            use serde_crate::{de, Deserializer, Serializer};

            pub fn serialize<A: SerdeAmountForOpt, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_pico_opt(s),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, A: SerdeAmountForOpt, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Option<A>, D::Error> {
                struct VisitOptAmt<X>(PhantomData<X>);

                impl<'de, X: SerdeAmountForOpt> de::Visitor<'de> for VisitOptAmt<X> {
                    type Value = Option<X>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        write!(formatter, "an Option<{}64>", X::type_prefix())
                    }

                    fn visit_none<E>(self) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(None)
                    }
                    fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
                    where
                        D: Deserializer<'de>,
                    {
                        Ok(Some(X::des_pico(d)?))
                    }
                }
                d.deserialize_option(VisitOptAmt::<A>(PhantomData))
            }
        }

        pub mod slice {
            //! Serialize `&[Amount]` and `&[SignedAmount]` as an array of numbers denoted in piconero.
            //! Use with `#[serde(default, serialize_with = "monero::util::amount::serde::as_pico::slice::serialize")]`.

            use super::super::SerdeAmountForSlice;
            use serde_crate::{ser::SerializeSeq, Serializer};

            pub fn serialize<A: SerdeAmountForSlice, S: Serializer>(
                a_slice: &[A],
                s: S,
            ) -> Result<S::Ok, S::Error> {
                let mut seq = s.serialize_seq(Some(a_slice.len()))?;

                for e in a_slice {
                    e.ser_pico_slice(&mut seq)?;
                }

                seq.end()
            }
        }

        pub mod vec {
            //! Deserialize an array of numbers (in piconero) into `Vec<Amount>` or
            //! `Vec<SignedAmount>`.
            //! It is possible to use `#[serde(default, deserialize_with = "monero::util::amount::serde::as_pico::vec::deserialize_amount")]`
            //! for `Vec<Amount>`, and `#[serde(default, deserialize_with = "monero::util::amount::serde::as_pico::vec::deserialize_signed_amount")]`
            //! for `Vec<SignedAmount>`.

            use super::super::{Amount, SignedAmount};
            use core::marker::PhantomData;
            use serde_crate::{de, Deserializer};

            /// Use with `#[serde(default, deserialize_with = "monero::util::amount::serde::as_pico::vec::deserialize_amount")]`.
            pub fn deserialize_amount<'d, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Vec<Amount>, D::Error> {
                struct VisitVecAmt(PhantomData<Amount>);

                impl<'de> de::Visitor<'de> for VisitVecAmt {
                    type Value = Vec<Amount>;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(formatter, "a Vec<u64>")
                    }

                    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
                    where
                        S: de::SeqAccess<'de>,
                    {
                        std::iter::repeat_with(|| seq.next_element())
                            .map_while(|e| e.transpose().map(|res| res.map(Amount::from_pico)))
                            .collect()
                    }
                }

                d.deserialize_seq(VisitVecAmt(PhantomData))
            }

            /// Use with `#[serde(default, deserialize_with = "monero::util::amount::serde::as_pico::vec::deserialize_signed_amount")]`.
            pub fn deserialize_signed_amount<'d, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Vec<SignedAmount>, D::Error> {
                struct VisitVecAmt(PhantomData<SignedAmount>);

                impl<'de> de::Visitor<'de> for VisitVecAmt {
                    type Value = Vec<SignedAmount>;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(formatter, "a Vec<i64>")
                    }

                    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
                    where
                        S: de::SeqAccess<'de>,
                    {
                        std::iter::repeat_with(|| seq.next_element())
                            .map_while(|e| {
                                e.transpose().map(|res| res.map(SignedAmount::from_pico))
                            })
                            .collect()
                    }
                }

                d.deserialize_seq(VisitVecAmt(PhantomData))
            }
        }
    }

    pub mod as_xmr {
        // methods are implementation of a standardized serde-specific signature
        #![allow(missing_docs)]

        //! Serialize and deserialize [`Amount`] as a string denominated in xmr.
        //! Use with `#[serde(with = "monero::util::amount::serde::as_xmr")]`.
        //!
        //! ```rust
        //! # use serde_crate::{Serialize, Deserialize};
        //! use monero::Amount;
        //!
        //! #[derive(Serialize, Deserialize)]
        //! # #[serde(crate = "serde_crate")]
        //! pub struct HasAmount {
        //!     #[serde(
        //!         default,
        //!         serialize_with = "monero::util::amount::serde::as_xmr::slice::serialize",
        //!         deserialize_with = "monero::util::amount::serde::as_xmr::vec::deserialize_amount"
        //!     )]
        //!     pub amounts: Vec<Amount>
        //! }
        //! ```
        //!
        //! [`Amount`]: crate::util::amount::Amount

        use super::SerdeAmount;
        use serde_crate::{Deserializer, Serializer};

        pub fn serialize<A: SerdeAmount, S: Serializer>(a: &A, s: S) -> Result<S::Ok, S::Error> {
            a.ser_xmr(s)
        }

        pub fn deserialize<'d, A: SerdeAmount, D: Deserializer<'d>>(d: D) -> Result<A, D::Error> {
            A::des_xmr(d)
        }

        pub mod opt {
            //! Serialize and deserialize [Option] as a number denominated in xmr.
            //! Use with `#[serde(default, with = "monero::util::amount::serde::as_xmr::opt")]`.

            use super::super::SerdeAmountForOpt;
            use core::fmt;
            use core::marker::PhantomData;
            use serde_crate::{de, Deserializer, Serializer};

            pub fn serialize<A: SerdeAmountForOpt, S: Serializer>(
                a: &Option<A>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                match *a {
                    Some(a) => a.ser_xmr_opt(s),
                    None => s.serialize_none(),
                }
            }

            pub fn deserialize<'d, A: SerdeAmountForOpt, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Option<A>, D::Error> {
                struct VisitOptAmt<X>(PhantomData<X>);

                impl<'de, X: SerdeAmountForOpt> de::Visitor<'de> for VisitOptAmt<X> {
                    type Value = Option<X>;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        write!(formatter, "an Option<String>")
                    }

                    fn visit_none<E>(self) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        Ok(None)
                    }
                    fn visit_some<D>(self, d: D) -> Result<Self::Value, D::Error>
                    where
                        D: Deserializer<'de>,
                    {
                        Ok(Some(X::des_xmr(d)?))
                    }
                }
                d.deserialize_option(VisitOptAmt::<A>(PhantomData))
            }
        }

        pub mod slice {
            //! Serialize `&[Amount]` and `&[SignedAmount]` as an array of numbers denoted in xmr.
            //! Use with `#[serde(default, serialize_with = "monero::util::amount::serde::as_xmr::slice::serialize")]`.

            use super::super::SerdeAmountForSlice;
            use serde_crate::{ser::SerializeSeq, Serializer};

            pub fn serialize<A: SerdeAmountForSlice, S: Serializer>(
                a_slice: &[A],
                s: S,
            ) -> Result<S::Ok, S::Error> {
                let mut seq = s.serialize_seq(Some(a_slice.len()))?;

                for e in a_slice {
                    e.ser_xmr_slice(&mut seq)?;
                }

                seq.end()
            }
        }

        pub mod vec {
            //! Deserialize an array of numbers (in xmr) into `Vec<Amount>` or
            //! `Vec<SignedAmount>`.
            //! It is possible to use `#[serde(default, deserialize_with = "monero::util::amount::serde::as_xmr::vec::deserialize_amount")]`
            //! for `Vec<Amount>`, and `#[serde(default, deserialize_with = "monero::util::amount::serde::as_xmr::vec::deserialize_signed_amount")]`
            //! for `Vec<SignedAmount>`.

            use super::super::{super::Denomination, Amount, SignedAmount};
            use core::marker::PhantomData;
            use serde_crate::{de, Deserializer};

            /// Use with `#[serde(default, deserialize_with = "monero::util::amount::serde::as_xmr::vec::deserialize_amount")]`.
            pub fn deserialize_amount<'d, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Vec<Amount>, D::Error> {
                struct VisitVecAmt(PhantomData<Amount>);

                impl<'de> de::Visitor<'de> for VisitVecAmt {
                    type Value = Vec<Amount>;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(formatter, "a Vec<String>")
                    }

                    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
                    where
                        S: de::SeqAccess<'de>,
                    {
                        std::iter::repeat_with(|| seq.next_element())
                            .map_while(|e| {
                                e.transpose().map(|res| {
                                    res.and_then(|amt| {
                                        Amount::from_str_in(amt, Denomination::Monero)
                                            .map_err(|e| de::Error::custom(e.to_string()))
                                    })
                                })
                            })
                            .collect()
                    }
                }

                d.deserialize_seq(VisitVecAmt(PhantomData))
            }

            /// Use with `#[serde(default, deserialize_with = "monero::util::amount::serde::as_xmr::vec::deserialize_signed_amount")]`.
            pub fn deserialize_signed_amount<'d, D: Deserializer<'d>>(
                d: D,
            ) -> Result<Vec<SignedAmount>, D::Error> {
                struct VisitVecAmt(PhantomData<SignedAmount>);

                impl<'de> de::Visitor<'de> for VisitVecAmt {
                    type Value = Vec<SignedAmount>;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(formatter, "a Vec<String>")
                    }

                    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
                    where
                        S: de::SeqAccess<'de>,
                    {
                        std::iter::repeat_with(|| seq.next_element())
                            .map_while(|e| {
                                e.transpose().map(|res| {
                                    res.and_then(|amt| {
                                        SignedAmount::from_str_in(amt, Denomination::Monero)
                                            .map_err(|e| de::Error::custom(e.to_string()))
                                    })
                                })
                            })
                            .collect()
                    }
                }

                d.deserialize_seq(VisitVecAmt(PhantomData))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;
    use std::str::FromStr;

    #[cfg(feature = "serde")]
    use serde_test;

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

        assert_eq!(f(-100.0, D::Piconero), Err(AmountParsingError::Negative));
        assert_eq!(f(11.22, D::Piconero), Err(AmountParsingError::TooPrecise));
        assert_eq!(sf(-0.1, D::Piconero), Err(AmountParsingError::TooPrecise));
        assert_eq!(
            f(42.000_000_000_000_1, D::Monero),
            Err(AmountParsingError::TooPrecise)
        );
        assert_eq!(
            sf(-184467440738.0, D::Monero),
            Err(AmountParsingError::TooBig)
        );
        assert_eq!(
            f(18446744073709551617.0, D::Piconero),
            Err(AmountParsingError::TooBig)
        );
        assert_eq!(
            f(
                SignedAmount::max_value().to_float_in(D::Piconero).unwrap() + 1.0,
                D::Piconero
            ),
            Err(AmountParsingError::TooBig)
        );
        assert_eq!(
            f(
                Amount::max_value().to_float_in(D::Piconero).unwrap() + 1.0,
                D::Piconero
            ),
            Err(AmountParsingError::TooBig)
        );

        let xmr = move |f| SignedAmount::from_xmr(f).unwrap();
        assert_eq!(xmr(2.5).to_float_in(D::Monero).unwrap(), 2.5);
        assert_eq!(xmr(-2.5).to_float_in(D::Millinero).unwrap(), -2500.0);
        assert_eq!(xmr(-2.5).to_float_in(D::Micronero).unwrap(), -2500000.0);
        assert_eq!(xmr(-2.5).to_float_in(D::Nanonero).unwrap(), -2500000000.0);
        assert_eq!(xmr(2.5).to_float_in(D::Piconero).unwrap(), 2500000000000.0);

        let xmr = move |f| Amount::from_xmr(f).unwrap();
        assert_eq!(
            &xmr(0.0012).to_float_in(D::Monero).unwrap().to_string(),
            "0.0012"
        )
    }

    #[test]
    fn parsing() {
        use super::AmountParsingError as E;
        let xmr = Denomination::Monero;
        let pico = Denomination::Piconero;
        let p = Amount::from_str_in;
        let sp = SignedAmount::from_str_in;

        assert_eq!(p("x", xmr), Err(E::InvalidCharacter('x')));
        assert_eq!(p("-", xmr), Err(E::InvalidFormat));
        assert_eq!(sp("-", xmr), Err(E::InvalidFormat));
        assert_eq!(p("-1.0x", xmr), Err(E::InvalidCharacter('x')));
        assert_eq!(
            p("0.0 ", xmr),
            Err(AmountParsingError::InvalidCharacter(' '))
        );
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

        // make sure Piconero > i64::MAX is checked.
        let amount = Amount::from_pico(i64::MAX as u64);
        assert_eq!(
            Amount::from_str_in(&amount.to_string_in(pico).unwrap(), pico),
            Ok(amount)
        );
        assert_eq!(
            Amount::from_str_in(&(amount + Amount(1)).to_string_in(pico).unwrap(), pico),
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

        assert_eq!(
            Amount::ONE_XMR.to_string_in(D::Monero).unwrap(),
            "1.000000000000"
        );
        assert_eq!(
            Amount::ONE_XMR.to_string_in(D::Piconero).unwrap(),
            "1000000000000"
        );
        assert_eq!(
            Amount::ONE_PICO.to_string_in(D::Monero).unwrap(),
            "0.000000000001"
        );
        assert_eq!(
            SignedAmount::from_pico(-42)
                .to_string_in(D::Monero)
                .unwrap(),
            "-0.000000000042"
        );

        assert_eq!(
            Amount::ONE_XMR
                .to_string_with_denomination(D::Monero)
                .unwrap(),
            "1.000000000000 xmr"
        );
        assert_eq!(
            SignedAmount::ONE_XMR
                .to_string_with_denomination(D::Piconero)
                .unwrap(),
            "1000000000000 piconero"
        );
        assert_eq!(
            Amount::ONE_PICO
                .to_string_with_denomination(D::Monero)
                .unwrap(),
            "0.000000000001 xmr"
        );
        assert_eq!(
            SignedAmount::from_pico(-42)
                .to_string_with_denomination(D::Monero)
                .unwrap(),
            "-0.000000000042 xmr"
        );
    }

    #[test]
    fn test_unsigned_signed_conversion() {
        use super::AmountParsingError as E;
        let p = Amount::from_pico;
        let sp = SignedAmount::from_pico;

        assert_eq!(Amount::max_value().to_signed(), Err(E::TooBig));
        assert_eq!(p(i64::MAX as u64).to_signed(), Ok(sp(i64::MAX)));
        assert_eq!(p(0).to_signed(), Ok(sp(0)));
        assert_eq!(p(1).to_signed(), Ok(sp(1)));
        assert_eq!(p(1).to_signed(), Ok(sp(1)));
        assert_eq!(p(i64::MAX as u64 + 1).to_signed(), Err(E::TooBig));

        assert_eq!(sp(-1).to_unsigned(), Err(E::Negative));
        assert_eq!(sp(i64::MAX).to_unsigned(), Ok(p(i64::MAX as u64)));

        assert_eq!(sp(0).to_unsigned().unwrap().to_signed(), Ok(sp(0)));
        assert_eq!(sp(1).to_unsigned().unwrap().to_signed(), Ok(sp(1)));
        assert_eq!(
            sp(i64::MAX).to_unsigned().unwrap().to_signed(),
            Ok(sp(i64::MAX))
        );
    }

    #[test]
    fn from_str() {
        use super::AmountParsingError as E;
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
        let ua_pic = Amount::from_pico;
        let sa_str = SignedAmount::from_str_in;
        let sa_pic = SignedAmount::from_pico;

        assert_eq!(
            "0.500",
            Amount::from_pico(500).to_string_in(D::Nanonero).unwrap()
        );
        assert_eq!(
            "-0.500",
            SignedAmount::from_pico(-500)
                .to_string_in(D::Nanonero)
                .unwrap()
        );
        assert_eq!(
            "0.002535830000",
            Amount::from_pico(2535830000)
                .to_string_in(D::Monero)
                .unwrap()
        );
        assert_eq!(
            "-5",
            SignedAmount::from_pico(-5)
                .to_string_in(D::Piconero)
                .unwrap()
        );
        assert_eq!(
            "0.100000000000",
            Amount::from_pico(100_000_000_000)
                .to_string_in(D::Monero)
                .unwrap()
        );
        assert_eq!(
            "-10.000",
            SignedAmount::from_pico(-10_000)
                .to_string_in(D::Nanonero)
                .unwrap()
        );

        assert_eq!(
            ua_str(&ua_pic(0).to_string_in(D::Piconero).unwrap(), D::Piconero),
            Ok(ua_pic(0))
        );
        assert_eq!(
            ua_str(&ua_pic(500).to_string_in(D::Monero).unwrap(), D::Monero),
            Ok(ua_pic(500))
        );
        assert_eq!(
            ua_str(
                &ua_pic(21_000_000).to_string_in(D::Nanonero).unwrap(),
                D::Nanonero
            ),
            Ok(ua_pic(21_000_000))
        );
        assert_eq!(
            ua_str(&ua_pic(1).to_string_in(D::Micronero).unwrap(), D::Micronero),
            Ok(ua_pic(1))
        );
        assert_eq!(
            ua_str(
                &ua_pic(1_000_000_000_000)
                    .to_string_in(D::Millinero)
                    .unwrap(),
                D::Millinero
            ),
            Ok(ua_pic(1_000_000_000_000))
        );
        assert_eq!(
            ua_str(
                &ua_pic(u64::MAX).to_string_in(D::Millinero).unwrap(),
                D::Millinero
            ),
            Err(AmountParsingError::TooBig)
        );

        assert_eq!(
            sa_str(
                &sa_pic(-1).to_string_in(D::Micronero).unwrap(),
                D::Micronero
            ),
            Ok(sa_pic(-1))
        );

        assert_eq!(
            sa_str(
                &sa_pic(i64::MAX).to_string_in(D::Piconero).unwrap(),
                D::Micronero
            ),
            Err(AmountParsingError::TooBig)
        );
        // Test an overflow bug in `abs()`
        assert_eq!(
            sa_str(
                &sa_pic(i64::MIN).to_string_in(D::Piconero).unwrap(),
                D::Micronero
            ),
            Err(AmountParsingError::TooBig)
        );
    }

    #[test]
    fn to_string_with_denomination_from_str_roundtrip() {
        use super::Denomination as D;
        let amt = Amount::from_pico(42);
        let denom = Amount::to_string_with_denomination;
        assert_eq!(Amount::from_str(&denom(amt, D::Monero).unwrap()), Ok(amt));
        assert_eq!(
            Amount::from_str(&denom(amt, D::Millinero).unwrap()),
            Ok(amt)
        );
        assert_eq!(
            Amount::from_str(&denom(amt, D::Micronero).unwrap()),
            Ok(amt)
        );
        assert_eq!(Amount::from_str(&denom(amt, D::Nanonero).unwrap()), Ok(amt));
        assert_eq!(Amount::from_str(&denom(amt, D::Piconero).unwrap()), Ok(amt));

        assert_eq!(
            Amount::from_str("42 piconero XMR"),
            Err(AmountParsingError::InvalidFormat)
        );
        assert_eq!(
            SignedAmount::from_str("-42 piconero XMR"),
            Err(AmountParsingError::InvalidFormat)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_pico() {
        use serde_crate::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(crate = "serde_crate")]
        struct T {
            #[serde(with = "super::serde::as_pico")]
            pub amt: Amount,
            #[serde(with = "super::serde::as_pico")]
            pub samt: SignedAmount,
        }
        serde_test::assert_tokens(
            &T {
                amt: Amount::from_pico(123456789),
                samt: SignedAmount::from_pico(-123456789),
            },
            &[
                serde_test::Token::Struct { name: "T", len: 2 },
                serde_test::Token::Str("amt"),
                serde_test::Token::U64(123456789),
                serde_test::Token::Str("samt"),
                serde_test::Token::I64(-123456789),
                serde_test::Token::StructEnd,
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_pico_opt() {
        use serde_crate::{Deserialize, Serialize};
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
        #[serde(crate = "serde_crate")]
        struct T {
            #[serde(default, with = "super::serde::as_pico::opt")]
            pub amt: Option<Amount>,
            #[serde(default, with = "super::serde::as_pico::opt")]
            pub samt: Option<SignedAmount>,
        }

        let with = T {
            amt: Some(Amount::from_pico(2_500_000_000_000)),
            samt: Some(SignedAmount::from_pico(-2_500_000_000_000)),
        };
        let without = T {
            amt: None,
            samt: None,
        };

        // Test Roundtripping
        for s in [&with, &without].iter() {
            let v = serde_json::to_string(s).unwrap();
            let w: T = serde_json::from_str(&v).unwrap();
            assert_eq!(w, **s);
        }

        let t: T =
            serde_json::from_str("{\"amt\": 2500000000000, \"samt\": -2500000000000}").unwrap();
        assert_eq!(t, with);

        let t: T = serde_json::from_str("{}").unwrap();
        assert_eq!(t, without);

        let value_with: serde_json::Value =
            serde_json::from_str("{\"amt\": 2500000000000, \"samt\": -2500000000000}").unwrap();
        assert_eq!(with, serde_json::from_value(value_with).unwrap());

        let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert_eq!(without, serde_json::from_value(value_without).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_pico_slice_serialize() {
        use serde_crate::Serialize;

        #[derive(Serialize, PartialEq, Debug, Eq)]
        #[serde(crate = "serde_crate")]
        struct T<'a> {
            #[serde(default, serialize_with = "super::serde::as_pico::slice::serialize")]
            pub amt1: Vec<Amount>,
            #[serde(default, serialize_with = "super::serde::as_pico::slice::serialize")]
            pub amt2: [Amount; 2],
            #[serde(default, serialize_with = "super::serde::as_pico::slice::serialize")]
            pub amt3: &'a [Amount],

            #[serde(default, serialize_with = "super::serde::as_pico::slice::serialize")]
            pub samt1: Vec<SignedAmount>,
            #[serde(default, serialize_with = "super::serde::as_pico::slice::serialize")]
            pub samt2: [SignedAmount; 2],
            #[serde(default, serialize_with = "super::serde::as_pico::slice::serialize")]
            pub samt3: &'a [SignedAmount],
        }
        let with = T {
            amt1: vec![
                Amount::from_pico(1_000_000_000),
                Amount::from_pico(2_000_000_000),
            ],
            amt2: [
                Amount::from_pico(3_000_000_000),
                Amount::from_pico(4_000_000_000),
            ],
            amt3: &[
                Amount::from_pico(5_000_000_000),
                Amount::from_pico(6_000_000_000),
            ],
            samt1: vec![
                SignedAmount::from_pico(-1_000_000_000),
                SignedAmount::from_pico(-2_000_000_000),
            ],
            samt2: [
                SignedAmount::from_pico(-3_000_000_000),
                SignedAmount::from_pico(-4_000_000_000),
            ],
            samt3: &[
                SignedAmount::from_pico(-5_000_000_000),
                SignedAmount::from_pico(-6_000_000_000),
            ],
        };
        let without = T {
            amt1: vec![],
            amt2: [
                Amount::from_pico(3_000_000_000),
                Amount::from_pico(4_000_000_000),
            ], // cannot be empty
            amt3: &[],
            samt1: vec![],
            samt2: [
                SignedAmount::from_pico(-3_000_000_000),
                SignedAmount::from_pico(-4_000_000_000),
            ], // cannot be empty
            samt3: &[],
        };

        let expected_with = r#"{"amt1":[1000000000,2000000000],"amt2":[3000000000,4000000000],"amt3":[5000000000,6000000000],"samt1":[-1000000000,-2000000000],"samt2":[-3000000000,-4000000000],"samt3":[-5000000000,-6000000000]}"#;
        assert_eq!(serde_json::to_string(&with).unwrap(), expected_with);

        let expected_without = r#"{"amt1":[],"amt2":[3000000000,4000000000],"amt3":[],"samt1":[],"samt2":[-3000000000,-4000000000],"samt3":[]}"#;
        assert_eq!(serde_json::to_string(&without).unwrap(), expected_without);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_pico_vec_deserialize() {
        use serde_crate::Deserialize;

        #[derive(Deserialize, PartialEq, Debug, Eq)]
        #[serde(crate = "serde_crate")]
        struct T {
            #[serde(
                default,
                deserialize_with = "super::serde::as_pico::vec::deserialize_amount"
            )]
            pub amt1: Vec<Amount>,
            #[serde(
                default,
                deserialize_with = "super::serde::as_pico::vec::deserialize_amount"
            )]
            pub amt2: Vec<Amount>,

            #[serde(
                default,
                deserialize_with = "super::serde::as_pico::vec::deserialize_signed_amount"
            )]
            pub samt1: Vec<SignedAmount>,
            #[serde(
                default,
                deserialize_with = "super::serde::as_pico::vec::deserialize_signed_amount"
            )]
            pub samt2: Vec<SignedAmount>,
        }

        let t = T {
            amt1: vec![Amount(1_000)],
            amt2: vec![],
            samt1: vec![SignedAmount(-1_000)],
            samt2: vec![],
        };

        let t_str = r#"{"amt1": [1000], "amt2": [], "samt1": [-1000], "samt2": []}"#;
        let t_from_str: T = serde_json::from_str(t_str).unwrap();
        assert_eq!(t_from_str, t);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_pico_vec_deserialize_invalid_amounts_error() {
        use serde_crate::Deserialize;

        #[derive(Deserialize, PartialEq, Debug, Eq)]
        #[serde(crate = "serde_crate")]
        struct T {
            #[serde(
                default,
                deserialize_with = "super::serde::as_pico::vec::deserialize_amount"
            )]
            pub amt: Vec<Amount>,

            #[serde(
                default,
                deserialize_with = "super::serde::as_pico::vec::deserialize_signed_amount"
            )]
            pub samt: Vec<SignedAmount>,
        }

        let t_str = r#"{"amt": [], "samt": [18446744073709551615]}"#;
        let t: Result<T, serde_json::Error> = serde_json::from_str(t_str);
        let t_err = t.unwrap_err();
        assert!(t_err.is_data());
        assert_eq!(
            t_err.to_string(),
            "invalid value: integer `18446744073709551615`, expected i64 at line 1 column 41"
        );

        let t_str = r#"{"amt": [], "samt": 1}"#;
        let t: Result<T, serde_json::Error> = serde_json::from_str(t_str);
        let t_err = t.unwrap_err();
        assert!(t_err.is_data());
        assert_eq!(
            t_err.to_string(),
            "invalid type: integer `1`, expected a Vec<i64> at line 1 column 21"
        );

        let t_str = r#"{"amt": [-1000], "samt": []}"#;
        let t: Result<T, serde_json::Error> = serde_json::from_str(t_str);
        let t_err = t.unwrap_err();
        assert!(t_err.is_data());
        assert_eq!(
            t_err.to_string(),
            "invalid value: integer `-1000`, expected u64 at line 1 column 14"
        );

        let t_str = r#"{"amt": 1, "samt": []}"#;
        let t: Result<T, serde_json::Error> = serde_json::from_str(t_str);
        let t_err = t.unwrap_err();
        assert!(t_err.is_data());
        assert_eq!(
            t_err.to_string(),
            "invalid type: integer `1`, expected a Vec<u64> at line 1 column 9"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_xmr() {
        use serde_crate::{Deserialize, Serialize};
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        #[serde(crate = "serde_crate")]
        struct T {
            #[serde(with = "super::serde::as_xmr")]
            pub amt: Amount,
            #[serde(with = "super::serde::as_xmr")]
            pub samt: SignedAmount,
        }

        let orig = T {
            amt: Amount::from_pico(9_000_000_000_000_000_001),
            samt: SignedAmount::from_pico(-9_000_000_000_000_000_001),
        };

        let json = "{\"amt\": \"9000000.000000000001\", \
                   \"samt\": \"-9000000.000000000001\"}";
        let t: T = serde_json::from_str(json).unwrap();
        assert_eq!(t, orig);

        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(t, serde_json::from_value(value).unwrap());

        // errors
        let t: Result<T, serde_json::Error> =
            serde_json::from_str("{\"amt\": \"1000000.0000000000001\", \"samt\": \"1\"}");
        assert!(t
            .unwrap_err()
            .to_string()
            .contains(&AmountParsingError::TooPrecise.to_string()));
        let t: Result<T, serde_json::Error> =
            serde_json::from_str("{\"amt\": \"-1\", \"samt\": \"1\"}");
        assert!(t
            .unwrap_err()
            .to_string()
            .contains(&AmountParsingError::Negative.to_string()));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_xmr_opt() {
        use serde_crate::{Deserialize, Serialize};
        use serde_json;

        #[derive(Serialize, Deserialize, PartialEq, Debug, Eq)]
        #[serde(crate = "serde_crate")]
        struct T {
            #[serde(default, with = "super::serde::as_xmr::opt")]
            pub amt: Option<Amount>,
            #[serde(default, with = "super::serde::as_xmr::opt")]
            pub samt: Option<SignedAmount>,
        }

        let with = T {
            amt: Some(Amount::from_pico(2_500_000_000_000)),
            samt: Some(SignedAmount::from_pico(-2_500_000_000_000)),
        };
        let without = T {
            amt: None,
            samt: None,
        };

        // Test Roundtripping
        for s in [&with, &without].iter() {
            let v = serde_json::to_string(s).unwrap();
            let w: T = serde_json::from_str(&v).unwrap();
            assert_eq!(w, **s);
        }

        let t: T = serde_json::from_str("{\"amt\": \"2.5\", \"samt\": \"-2.5\"}").unwrap();
        assert_eq!(t, with);

        let t: T = serde_json::from_str("{}").unwrap();
        assert_eq!(t, without);

        let value_with: serde_json::Value =
            serde_json::from_str("{\"amt\": \"2.5\", \"samt\": \"-2.5\"}").unwrap();
        assert_eq!(with, serde_json::from_value(value_with).unwrap());

        let value_without: serde_json::Value = serde_json::from_str("{}").unwrap();
        assert_eq!(without, serde_json::from_value(value_without).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_xmr_slice_serialize() {
        use serde_crate::Serialize;

        #[derive(Serialize, PartialEq, Debug, Eq)]
        #[serde(crate = "serde_crate")]
        struct T<'a> {
            #[serde(default, serialize_with = "super::serde::as_xmr::slice::serialize")]
            pub amt1: Vec<Amount>,
            #[serde(default, serialize_with = "super::serde::as_xmr::slice::serialize")]
            pub amt2: [Amount; 2],
            #[serde(default, serialize_with = "super::serde::as_xmr::slice::serialize")]
            pub amt3: &'a [Amount],

            #[serde(default, serialize_with = "super::serde::as_xmr::slice::serialize")]
            pub samt1: Vec<SignedAmount>,
            #[serde(default, serialize_with = "super::serde::as_xmr::slice::serialize")]
            pub samt2: [SignedAmount; 2],
            #[serde(default, serialize_with = "super::serde::as_xmr::slice::serialize")]
            pub samt3: &'a [SignedAmount],
        }
        let with = T {
            amt1: vec![
                Amount::from_pico(1_000_000_000),
                Amount::from_pico(2_000_000_000),
            ],
            amt2: [
                Amount::from_pico(3_000_000_000),
                Amount::from_pico(4_000_000_000),
            ],
            amt3: &[
                Amount::from_pico(5_000_000_000),
                Amount::from_pico(6_000_000_000),
            ],
            samt1: vec![
                SignedAmount::from_pico(-1_000_000_000),
                SignedAmount::from_pico(-2_000_000_000),
            ],
            samt2: [
                SignedAmount::from_pico(-3_000_000_000),
                SignedAmount::from_pico(-4_000_000_000),
            ],
            samt3: &[
                SignedAmount::from_pico(-5_000_000_000),
                SignedAmount::from_pico(-6_000_000_000),
            ],
        };
        let without = T {
            amt1: vec![],
            amt2: [
                Amount::from_pico(3_000_000_000),
                Amount::from_pico(4_000_000_000),
            ], // cannot be empty
            amt3: &[],
            samt1: vec![],
            samt2: [
                SignedAmount::from_pico(-3_000_000_000),
                SignedAmount::from_pico(-4_000_000_000),
            ], // cannot be empty
            samt3: &[],
        };

        let expected_with = r#"{"amt1":["0.001000000000","0.002000000000"],"amt2":["0.003000000000","0.004000000000"],"amt3":["0.005000000000","0.006000000000"],"samt1":["-0.001000000000","-0.002000000000"],"samt2":["-0.003000000000","-0.004000000000"],"samt3":["-0.005000000000","-0.006000000000"]}"#;
        assert_eq!(serde_json::to_string(&with).unwrap(), expected_with);

        let expected_without = r#"{"amt1":[],"amt2":["0.003000000000","0.004000000000"],"amt3":[],"samt1":[],"samt2":["-0.003000000000","-0.004000000000"],"samt3":[]}"#;
        assert_eq!(serde_json::to_string(&without).unwrap(), expected_without);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_xmr_vec_deserialize() {
        use serde_crate::Deserialize;

        #[derive(Deserialize, PartialEq, Debug, Eq)]
        #[serde(crate = "serde_crate")]
        struct T {
            #[serde(
                default,
                deserialize_with = "super::serde::as_xmr::vec::deserialize_amount"
            )]
            pub amt1: Vec<Amount>,
            #[serde(
                default,
                deserialize_with = "super::serde::as_xmr::vec::deserialize_amount"
            )]
            pub amt2: Vec<Amount>,

            #[serde(
                default,
                deserialize_with = "super::serde::as_xmr::vec::deserialize_signed_amount"
            )]
            pub samt1: Vec<SignedAmount>,
            #[serde(
                default,
                deserialize_with = "super::serde::as_xmr::vec::deserialize_signed_amount"
            )]
            pub samt2: Vec<SignedAmount>,
        }

        let t = T {
            amt1: vec![Amount(1_000_000)],
            amt2: vec![],
            samt1: vec![SignedAmount(-1_000_000)],
            samt2: vec![],
        };

        let t_str = r#"{"amt1": ["0.000001"], "amt2": [], "samt1": ["-0.000001"], "samt2": []}"#;
        let t_from_str: T = serde_json::from_str(t_str).unwrap();
        assert_eq!(t_from_str, t);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_as_xmr_vec_deserialize_invalid_amounts_error() {
        use serde_crate::Deserialize;

        #[derive(Deserialize, PartialEq, Debug, Eq)]
        #[serde(crate = "serde_crate")]
        struct T {
            #[serde(
                default,
                deserialize_with = "super::serde::as_xmr::vec::deserialize_amount"
            )]
            pub amt: Vec<Amount>,

            #[serde(
                default,
                deserialize_with = "super::serde::as_xmr::vec::deserialize_signed_amount"
            )]
            pub samt: Vec<SignedAmount>,
        }

        // `samt` is a vector of `SignedAmount`, and `SignedAmount` holds a `i64`.
        // `18446744073709551615` is the largest value of a `u64` can hold (see https://doc.rust-lang.org/std/u64/constant.MAX.html),
        // and thus a `i64` cannot hold this value, so an error must happen when deserializing (note that any value greater than
        // 9_223_372_036_854_775_807 could be used to trigger the error - as per https://doc.rust-lang.org/std/i64/constant.MAX.html)
        // Another way to see that is that no `u64` to `i64` casting is happenning, which would
        // cause overflow wrapping, causing wrong representation.
        let t_str = r#"{"amt": [], "samt": ["18446744073709551615"]}"#;
        let t: Result<T, serde_json::Error> = serde_json::from_str(t_str);
        let t_err = t.unwrap_err();
        assert!(t_err.is_data());
        assert_eq!(
            t_err.to_string(),
            "Amount is too big to fit inside the type at line 1 column 44"
        );

        let t_str = r#"{"amt": [], "samt": 1}"#;
        let t: Result<T, serde_json::Error> = serde_json::from_str(t_str);
        let t_err = t.unwrap_err();
        assert!(t_err.is_data());
        assert_eq!(
            t_err.to_string(),
            "invalid type: integer `1`, expected a Vec<String> at line 1 column 21"
        );

        // `amt` is a vector of `Amount`, and `Amount` holds a `u64`, but `-0.001` is a signed value. Like
        // above, this test makes sure no `i64` to `u64` casting is happening, which would cause
        // wrong representation.
        let t_str = r#"{"amt": ["-0.001"], "samt": []}"#;
        let t: Result<T, serde_json::Error> = serde_json::from_str(t_str);
        let t_err = t.unwrap_err();
        assert!(t_err.is_data());
        assert_eq!(t_err.to_string(), "Amount is negative at line 1 column 18");

        let t_str = r#"{"amt": 1, "samt": []}"#;
        let t: Result<T, serde_json::Error> = serde_json::from_str(t_str);
        let t_err = t.unwrap_err();
        assert!(t_err.is_data());
        assert_eq!(
            t_err.to_string(),
            "invalid type: integer `1`, expected a Vec<String> at line 1 column 9"
        );
    }
}
