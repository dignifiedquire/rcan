use anyhow::Result;
use serde::de::DeserializeOwned;
use ssh_encoding::{pem::PemLabel, Decode, DecodePem, Encode, EncodePem};

use crate::{chain::RcanChain, Capability};

impl<C: Capability> RcanChain<C> {
    pub fn from_pem(s: &str) -> Result<Self>
    where
        C: DeserializeOwned,
    {
        let token = RcanChain::decode_pem(&s)?;
        Ok(token)
    }

    pub fn to_pem(&self) -> Result<String> {
        let s = self.encode_pem_string(Default::default())?;
        Ok(s)
    }

    #[cfg(feature = "fs")]
    pub async fn read_from_file(path: impl AsRef<std::path::Path>) -> Result<Self>
    where
        C: DeserializeOwned,
    {
        let s = tokio::fs::read_to_string(path).await?;
        Self::from_pem(&s)
    }

    #[cfg(feature = "fs")]
    pub async fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let s = self.to_pem()?;
        tokio::fs::write(path, s).await?;
        Ok(())
    }
}

impl<C: Capability> Encode for RcanChain<C> {
    fn encoded_len(&self) -> std::result::Result<usize, ssh_encoding::Error> {
        Ok(RcanChain::encoded_len(self))
    }

    fn encode(
        &self,
        writer: &mut impl ssh_encoding::Writer,
    ) -> std::result::Result<(), ssh_encoding::Error> {
        let bytes = RcanChain::encode(self);
        writer.write(&bytes)
    }
}

impl<C: Capability + DeserializeOwned> Decode for RcanChain<C> {
    type Error = anyhow::Error;

    fn decode(reader: &mut impl ssh_encoding::Reader) -> Result<Self> {
        let len = reader.remaining_len();
        let mut bytes = vec![0u8; len];
        reader.read(&mut bytes)?;
        RcanChain::decode(&bytes)
    }
}

impl<C> PemLabel for RcanChain<C> {
    const PEM_LABEL: &'static str = "RCAN CHAIN V1";
}
