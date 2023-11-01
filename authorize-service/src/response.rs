use super::*;

use snarkvm::prelude::IoResult;
use snarkvm::synthesizer::Authorization;
use std::io::{Read, Write};

pub struct AuthorizeResponse<N: Network> {
    pub function_authorization: Authorization<N>,
    pub fee_authorization: Authorization<N>,
}

impl<N: Network> ToBytes for AuthorizeResponse<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()>
    where
        Self: Sized,
    {
        self.function_authorization.write_le(&mut writer)?;
        self.fee_authorization.write_le(&mut writer)
    }
}

impl<N: Network> FromBytes for AuthorizeResponse<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self>
    where
        Self: Sized,
    {
        let function_authorization = Authorization::read_le(&mut reader)?;
        let fee_authorization = Authorization::read_le(&mut reader)?;
        Ok(Self {
            function_authorization,
            fee_authorization,
        })
    }
}
