use std::{
    ops::Add,
    time::{Duration, SystemTime},
};

// TODO: better error management
use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::{
    ed25519::signature::Signer, Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub const VERSION: u8 = 1;

/// We allow arbitrary capabilities.
///
/// An example for a type implementing this trait might be the enum
/// for some RPC requests.
///
/// Capabilities are restricted. `can_delegate` is what implements these restrictions.
///
/// The `Capability` must be serializable so it can be used in an rcan, which is signed.
pub trait Capability: Serialize {
    /// Returns `false` this is not allowed with given
    /// capability, otherwise returns `true`.
    fn can_delegate(&self, capability: &Self) -> bool;
}

/// An authorizer for invocations.
///
/// This represents an identity in the form of a public key.
/// This public key will always be the same as the original issuer of
/// the capabilities that are invoked against the authorizer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Authorizer {
    // Might even make that `SigningKey` and allow it to `sign` rcans?
    identity: VerifyingKey,
}

impl Authorizer {
    /// Constructs a new authorizer for given identity.
    pub fn new(identity: VerifyingKey) -> Self {
        Self { identity }
    }

    /// Verifies an invocation of a capability owned by this authorizer,
    /// that may have been passed through delegations in a proof chain
    /// and was finally signed back to us from given `invoker`.
    ///
    /// Make sure to verify that the `invoker` signed and authenticated the
    /// message containing the `capability`.
    pub fn check_invocation_from<C: Capability>(
        &self,
        invoker: VerifyingKey,
        capability: C,
        proof_chain: &[&Rcan<C>],
    ) -> Result<()> {
        let now = SystemTime::now().elapsed()?.as_secs();
        // We require that proof chains are provided "back-to-front".
        // So they start with the owner of the capability, then
        // proceed with the next item in the chain.
        let mut current_issuer_target = &self.identity;
        for proof in proof_chain {
            // Verify proof chain issuer/audience integrity:
            let issuer = &proof.payload.issuer;
            let audience = &proof.payload.audience;
            ensure!(
                issuer == current_issuer_target,
                "invocation failed: expected proof to be issued by {}, but was issued by {}",
                hex::encode(current_issuer_target),
                hex::encode(issuer),
            );

            // Verify each proof's time validity:
            let expiry = &proof.payload.valid_until;
            ensure!(
                expiry.is_valid_at(now),
                "invocation failed: proof expired at {expiry}"
            );

            // Verify that the capability is actually reached through:
            ensure!(
                proof.payload.capability_key() == &self.identity,
                "invocation failed: proof is missing delegation for capability of {}",
                hex::encode(self.identity)
            );

            // Verify that the capability doesn't break out of capabilitys:
            ensure!(
                capability.can_delegate(proof.payload.capability()),
                "invocation failed"
            );

            // Continue checking the proof chain's integrity with this
            // delegation's audience as the next issuer target:
            current_issuer_target = audience;
        }

        ensure!(
        &invoker == current_issuer_target,
        "invocation failed: expected delegation chain to end in the connection's owner {}, but the connection is authenticated by {} instead",
        hex::encode(invoker),
        hex::encode(current_issuer_target),
    );

        Ok(())
    }
}

/// A token for attenuated capability delegations
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Rcan<C> {
    /// The actual content.
    pub payload: Payload<C>,
    /// Signature over the serialized payload.
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize, derive_more::Debug, PartialEq, Eq)]
pub struct Payload<C> {
    /// The issuer
    #[debug("{}", hex::encode(issuer))]
    issuer: VerifyingKey,
    /// The intended audience
    #[debug("{}", hex::encode(audience))]
    audience: VerifyingKey,
    /// Delegated capability
    capability: (VerifyingKey, C),
    /// Valid until unix timestamp in seconds.
    valid_until: Expires,
}

impl<C> Payload<C> {
    pub fn capability(&self) -> &C {
        &self.capability.1
    }

    pub fn capability_key(&self) -> &VerifyingKey {
        &self.capability.0
    }
}

/// When an rcan expires
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, derive_more::Display)]
pub enum Expires {
    /// Never expires
    #[display("never")]
    Never,
    /// Valid until given unix timestamp in seconds
    #[display("{_0}")]
    At(u64),
}

pub struct RcanBuilder<'s, C> {
    issuer: &'s SigningKey,
    audience: VerifyingKey,
    capability: (VerifyingKey, C),
}

impl<C> Rcan<C> {
    pub fn issuing_builder(
        issuer: &SigningKey,
        audience: VerifyingKey,
        capability: C,
    ) -> RcanBuilder<'_, C> {
        let att_key = issuer.verifying_key();
        RcanBuilder {
            issuer,
            audience,
            capability: (att_key, capability),
        }
    }

    pub fn delegating_builder(
        issuer: &SigningKey,
        audience: VerifyingKey,
        owner: VerifyingKey,
        capability: C,
    ) -> RcanBuilder<'_, C> {
        RcanBuilder {
            issuer,
            audience,
            capability: (owner, capability),
        }
    }

    pub fn encode(&self) -> Vec<u8>
    where
        C: Serialize,
    {
        postcard::to_extend(&self, vec![VERSION]).expect("vec")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self>
    where
        C: DeserializeOwned,
    {
        let Some(version) = bytes.first() else {
            bail!("cannot decode, token is empty");
        };
        ensure!(*version == VERSION, "invalid version: {}", version);

        let rcan: Self = postcard::from_bytes(&bytes[1..]).context("decoding")?;

        // Verify the signature
        let signed = &bytes[..bytes.len() - SIGNATURE_LENGTH]; // make sure to sign the version, too
        rcan.payload.issuer.verify_strict(signed, &rcan.signature)?;

        Ok(rcan)
    }

    pub fn audience(&self) -> &VerifyingKey {
        &self.payload.audience
    }

    pub fn issuer(&self) -> &VerifyingKey {
        &self.payload.issuer
    }

    pub fn capability(&self) -> &C {
        self.payload.capability()
    }

    pub fn capability_key(&self) -> &VerifyingKey {
        self.payload.capability_key()
    }
}

impl<C> RcanBuilder<'_, C> {
    pub fn sign(self, valid_until: Expires) -> Rcan<C>
    where
        C: Serialize,
    {
        let payload = Payload {
            issuer: self.issuer.verifying_key(),
            audience: self.audience,
            capability: self.capability,
            valid_until,
        };

        let to_sign = postcard::to_extend(&payload, vec![VERSION]).expect("vec");
        let signature = self.issuer.sign(&to_sign);

        Rcan { signature, payload }
    }
}

impl Expires {
    pub fn valid_for(duration: Duration) -> Self {
        Self::At(
            SystemTime::now()
                .elapsed()
                .expect("now is after UNIX_EPOCH")
                .add(duration)
                .as_secs(),
        )
    }

    pub fn is_valid_at(&self, time: u64) -> bool {
        match self {
            Expires::Never => true,
            Expires::At(expiry) => *expiry >= time,
        }
    }
}

#[cfg(test)]
mod test {
    use testresult::TestResult;

    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    #[repr(u8)]
    enum Rpc {
        Read = 1,
        ReadWrite = 2,
        /// Read, ReadWrite, and any "future ones" that we might not have thought of yet.
        All = 0,
    }

    impl Capability for Rpc {
        fn can_delegate(&self, capability: &Self) -> bool {
            match (capability, self) {
                (Rpc::Read, Rpc::Read) => true,
                (Rpc::Read, _) => false,
                (Rpc::ReadWrite, _) => true, // all operations are allowed by read-write in the current system
                (Rpc::All, _) => true,       // all RPC operations are allowed by definition
            }
        }
    }

    #[test]
    fn test_simple_capabilitys() {
        assert!(Rpc::Read.can_delegate(&Rpc::Read));
        assert!(!Rpc::ReadWrite.can_delegate(&Rpc::Read),);
        assert!(Rpc::ReadWrite.can_delegate(&Rpc::ReadWrite),);
    }

    #[test]
    fn test_rcan_encoding() -> TestResult {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::issuing_builder(&issuer, audience.verifying_key(), Rpc::ReadWrite)
            .sign(Expires::Never);

        println!("{}", hex::encode(rcan.encode()));

        let expected: String = [
            // Version
            "01",
            // Issuer
            "203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            // Audience
            "208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            // Capability key (equal to issuer)
            "203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            // Capability
            "0100",
            // Signature
            "063d18ba38e3fa41b63c35e2986bf3f4a03f655c96340c018338272466bbf65f772d58c7670c8eb57cf5210f1629a0f0058b038b5c02fc3bdc96662665d9ea0d",
        ]
        .join("");

        assert_eq!(hex::encode(rcan.encode()), expected);
        assert_eq!(Rcan::decode(&rcan.encode())?, rcan);
        Ok(())
    }

    #[test]
    fn test_rcan_invocation() -> TestResult {
        let service = SigningKey::from_bytes(&[0u8; 32]);
        let alice = SigningKey::from_bytes(&[1u8; 32]);
        let bob = SigningKey::from_bytes(&[2u8; 32]);

        // The service gives alice access to everything for 60 seconds
        let service_rcan = Rcan::issuing_builder(&service, alice.verifying_key(), Rpc::All)
            .sign(Expires::valid_for(Duration::from_secs(60)));
        // alice gives attenuated (only read access) to bob, but doesn't care for how long still
        let friend_rcan = Rcan::delegating_builder(
            &alice,
            bob.verifying_key(),
            service.verifying_key(),
            Rpc::Read,
        )
        .sign(Expires::Never);
        // bob can now pass the authorization test for the service
        let service_auth = Authorizer::new(service.verifying_key());
        assert!(service_auth
            .check_invocation_from(
                bob.verifying_key(),
                Rpc::Read,
                &[&service_rcan, &friend_rcan],
            )
            .is_ok());

        // but bob doesn't have read-write access
        assert!(service_auth
            .check_invocation_from(
                bob.verifying_key(),
                Rpc::ReadWrite,
                &[&service_rcan, &friend_rcan]
            )
            .is_err());

        Ok(())
    }
}
