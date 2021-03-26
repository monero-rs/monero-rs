use crate::{
    consensus::encode::{Decodable, Encodable, Error},
    PrivateKey, PublicKey,
};
use std::io;

impl strict_encoding::StrictEncode for PublicKey {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        self.consensus_encode(&mut e)
            .map_err(strict_encoding::Error::from)
    }
}

impl strict_encoding::StrictDecode for PublicKey {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self::consensus_decode(&mut d).map_err(Error::from)?)
    }
}

impl strict_encoding::StrictEncode for PrivateKey {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        self.consensus_encode(&mut e)
            .map_err(strict_encoding::Error::from)
    }
}

impl strict_encoding::StrictDecode for PrivateKey {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self::consensus_decode(&mut d).map_err(Error::from)?)
    }
}

impl From<Error> for strict_encoding::Error {
    #[inline]
    fn from(e: Error) -> Self {
        strict_encoding::Error::DataIntegrityError(e.to_string())
    }
}
