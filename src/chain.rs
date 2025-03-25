use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{Authorizer, Capability, Expires, Rcan, VERSION};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct RcanChain<C>(Vec<Rcan<C>>);

impl<C> Default for RcanChain<C> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<C: Capability> RcanChain<C> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn from_rcan(rcan: Rcan<C>) -> Self {
        Self(vec![rcan])
    }

    pub fn iter(&self) -> impl Iterator<Item = &'_ Rcan<C>> + '_ {
        self.into_iter()
    }

    pub fn first_issuer(&self) -> Result<&VerifyingKey> {
        self.0
            .first()
            .map(|rcan| rcan.issuer())
            .context("rcan chain is empty")
    }

    pub fn final_audience(&self) -> Result<&VerifyingKey> {
        self.0
            .last()
            .map(|rcan| rcan.audience())
            .context("rcan chain is empty")
    }

    pub fn final_capability(&self) -> Result<&C> {
        self.0
            .last()
            .map(|rcan| rcan.capability())
            .context("rcan chain is empty")
    }

    pub fn verify_chain(&self) -> Result<()> {
        self.check_invocation_from(
            *self.first_issuer()?,
            *self.final_audience()?,
            self.final_capability()?,
        )
    }

    pub fn check_invocation_from(
        &self,
        root_issuer: VerifyingKey,
        invoker: VerifyingKey,
        capability: &C,
    ) -> Result<()> {
        if self.first_issuer()? != &root_issuer {
            bail!("invocation failed: root issuer does not match");
        }
        Authorizer::new(root_issuer)
            .check_invocation_from(invoker, capability, self)
            .context("not authorized")?;
        Ok(())
    }

    pub fn with_delegation(
        &self,
        issuer: &SigningKey,
        audience: VerifyingKey,
        capability: C,
        max_age: Duration,
    ) -> Result<Self>
    where
        C: Clone,
    {
        let root_issuer = self.first_issuer()?;
        self.check_invocation_from(*root_issuer, issuer.verifying_key(), &capability)?;

        let can = Rcan::delegating_builder(&issuer, audience, *root_issuer, capability)
            .sign(Expires::valid_for(max_age));
        let mut next_chain = self.0.clone();
        next_chain.push(can);
        Ok(Self(next_chain))
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_extend(self, vec![VERSION]).expect("vec")
    }

    pub fn encoded_len(&self) -> usize {
        postcard::experimental::serialized_size(self).unwrap() + 1
    }

    pub fn decode(bytes: &[u8]) -> Result<Self>
    where
        C: DeserializeOwned,
    {
        let Some(version) = bytes.first() else {
            bail!("cannot decode, token is empty");
        };
        ensure!(*version == VERSION, "invalid version: {}", version);
        let out: Self = postcard::from_bytes(&bytes[1..]).context("decoding")?;
        Ok(out)
    }
}

impl<'a, C> IntoIterator for &'a RcanChain<C> {
    type Item = &'a Rcan<C>;

    type IntoIter = std::slice::Iter<'a, Rcan<C>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0[..].into_iter()
    }
}
