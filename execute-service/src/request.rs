use super::*;

use snarkvm::prelude::{error, IoResult};
use std::io::{Read, Write};

#[derive(Clone, Debug)]
pub struct ExecuteRequest<N: Network> {
    pub function_authorization: Authorization<N>,
    pub fee_authorization: Authorization<N>,
    pub state_root: Option<N::StateRoot>,
    pub state_path: Option<StatePath<N>>,
}

impl<N: Network> FromBytes for ExecuteRequest<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self>
    where
        Self: Sized,
    {
        let function_authorization = Authorization::read_le(&mut reader)?;
        let fee_authorization = Authorization::read_le(&mut reader)?;
        let state_root = match u8::read_le(&mut reader)? {
            0 => None,
            1 => Some(N::StateRoot::read_le(&mut reader)?),
            _ => return Err(error("Invalid state root flag")),
        };
        let state_path = match u8::read_le(&mut reader)? {
            0 => None,
            1 => Some(StatePath::read_le(&mut reader)?),
            _ => return Err(error("Invalid state path flag")),
        };
        Ok(Self {
            function_authorization,
            fee_authorization,
            state_root,
            state_path,
        })
    }
}

impl<N: Network> ToBytes for ExecuteRequest<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()>
    where
        Self: Sized,
    {
        self.function_authorization.write_le(&mut writer)?;
        self.fee_authorization.write_le(&mut writer)?;
        match &self.state_root {
            None => 0u8.write_le(&mut writer)?,
            Some(state_root) => {
                1u8.write_le(&mut writer)?;
                state_root.write_le(&mut writer)?
            }
        }
        match &self.state_path {
            None => 0u8.write_le(&mut writer)?,
            Some(state_path) => {
                1u8.write_le(&mut writer)?;
                state_path.write_le(&mut writer)?
            }
        }
        Ok(())
    }
}
