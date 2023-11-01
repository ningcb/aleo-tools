use super::*;

use snarkvm::prelude::{Address, IoResult, U64};
use std::io::{Read, Write};

#[derive(Clone, Debug)]
pub struct AuthorizeRequest<N: Network> {
    pub private_key: PrivateKey<N>,
    pub recipient: Address<N>,
    pub amount_in_microcredits: U64<N>,
    pub priority_fee_in_microcredits: U64<N>,
}

impl<N: Network> FromBytes for AuthorizeRequest<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self>
        where
            Self: Sized,
    {
        let private_key = PrivateKey::read_le(&mut reader)?;
        let recipient = Address::read_le(&mut reader)?;
        let amount_in_microcredits = U64::read_le(&mut reader)?;
        let priority_fee_in_microcredits = U64::read_le(&mut reader)?;
        Ok(Self {
            private_key,
            recipient,
            amount_in_microcredits,
            priority_fee_in_microcredits,
        })
    }
}

impl<N: Network> ToBytes for AuthorizeRequest<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()>
    where
        Self: Sized,
    {
        self.private_key.write_le(&mut writer)?;
        self.recipient.write_le(&mut writer)?;
        self.amount_in_microcredits.write_le(&mut writer)?;
        self.priority_fee_in_microcredits.write_le(&mut writer)
    }
}
