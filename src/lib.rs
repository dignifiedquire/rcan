use std::collections::BTreeMap;
use std::ops::Add;
use std::time::{Duration, SystemTime};

// TODO: better error management
use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 1;

/// We allow arbitrary capabilities.
///
/// An example for a type implementing this trait might be the enum
/// for some RPC requests.
///
/// Capabilities are restricted by "attenuations", which are representations
/// of predicates on them. `allowed_by_attenuation` is what translates the
/// predicate representation into an actual predicate.
///
/// The `attenutation` must be serializable so it can be used in an rcan,
/// which is signed.
pub trait Capability {
    /// The representation of a restriction on this capability.
    type Attenuation: Serialize;

    /// Returns some `Err`, when this capability is not allowed with given
    /// attenuation, otherwise returns `Ok(())`.
    fn allowed_by_attenuation(&self, attenuation: &Self::Attenuation) -> Result<()>;
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
        proof_chain: &[&Rcan<C::Attenuation>],
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
            let Some(attenuation) = proof
                .payload
                .attenuations
                .get(&VerifyingKeyWrapper(self.identity))
            else {
                bail!(
                    "invocation failed: proof is missing delegation for capability of {}",
                    hex::encode(self.identity)
                );
            };

            // Verify that the capability doesn't break out of attenuations:
            capability
                .allowed_by_attenuation(attenuation)
                .context("invocation failed")?;

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
pub struct Rcan<A> {
    /// The actual content.
    pub payload: Payload<A>,
    /// Signature over the serialized payload.
    pub signature: Signature,
}

#[derive(Clone, Serialize, Deserialize, derive_more::Debug, PartialEq, Eq)]
pub struct Payload<A> {
    /// The issuer
    #[debug("{}", hex::encode(issuer))]
    issuer: VerifyingKey,
    /// The intended audience
    #[debug("{}", hex::encode(audience))]
    audience: VerifyingKey,
    /// Attenuations on delegated capabilities
    attenuations: BTreeMap<VerifyingKeyWrapper, A>,
    /// Valid until unix timestamp in seconds.
    valid_until: Expires,
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

pub struct RcanBuilder<'s, A> {
    issuer: &'s SigningKey,
    audience: VerifyingKey,
    attenuations: BTreeMap<VerifyingKeyWrapper, A>,
}

impl<A> Rcan<A> {
    pub fn builder(issuer: &SigningKey, audience: VerifyingKey) -> RcanBuilder<'_, A> {
        RcanBuilder {
            issuer,
            audience,
            attenuations: Default::default(),
        }
    }

    pub fn encode(&self) -> Vec<u8>
    where
        A: Serialize,
    {
        postcard::to_extend(&self, vec![VERSION]).expect("vec")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self>
    where
        A: DeserializeOwned,
    {
        let Some(version) = bytes.get(0) else {
            bail!("cannot decode, token is empty");
        };
        ensure!(*version == VERSION, "invalid version: {}", version);

        let rcan: Self = postcard::from_bytes(&bytes[1..]).context("decoding")?;

        // Verify the signature
        let signed = &bytes[..bytes.len() - SIGNATURE_LENGTH]; // make sure to sign the version, too
        rcan.payload
            .issuer
            .verify_strict(&signed, &rcan.signature)?;

        Ok(rcan)
    }
}

impl<A> RcanBuilder<'_, A> {
    pub fn issuing(mut self, attenuation: A) -> Self {
        self.attenuations.insert(
            VerifyingKeyWrapper(self.issuer.verifying_key()),
            attenuation,
        );
        self
    }

    pub fn delegating(mut self, owner: VerifyingKey, attenuation: A) -> Self {
        self.attenuations
            .insert(VerifyingKeyWrapper(owner), attenuation);
        self
    }

    pub fn sign(self, valid_until: Expires) -> Rcan<A>
    where
        A: Serialize,
    {
        let payload = Payload {
            issuer: self.issuer.verifying_key(),
            audience: self.audience,
            attenuations: self.attenuations,
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

// Private stuff

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Default, derive_more::Debug)]
#[repr(transparent)]
#[debug("{}", hex::encode(_0))]
struct VerifyingKeyWrapper(VerifyingKey);

impl PartialOrd for VerifyingKeyWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerifyingKeyWrapper {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use testresult::TestResult;

    use super::*;

    enum Rpc {
        Read { key: &'static str },
        Write { key: &'static str, value: u64 },
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    enum RpcAtt {
        Read = 1,
        ReadWrite = 2,
        /// Read, ReadWrite, and any "future ones" that we might not have thought of yet.
        All = 0,
    }

    impl Capability for Rpc {
        type Attenuation = RpcAtt;

        fn allowed_by_attenuation(&self, attenuation: &Self::Attenuation) -> Result<()> {
            match (attenuation, self) {
                (RpcAtt::Read, Rpc::Read { .. }) => Ok(()),
                (RpcAtt::Read, _) => Err(anyhow::anyhow!("Illegal invocation")),
                (RpcAtt::ReadWrite, _) => Ok(()), // all operations are allowed by read-write in the current system
                (RpcAtt::All, _) => Ok(()),       // all RPC operations are allowed by definition
            }
        }
    }

    #[test]
    fn test_simple_attenuations() {
        assert_matches!(
            Rpc::Read { key: "hello" }.allowed_by_attenuation(&RpcAtt::Read),
            Ok(_)
        );

        assert_matches!(
            Rpc::Write {
                key: "hello",
                value: 42
            }
            .allowed_by_attenuation(&RpcAtt::Read),
            Err(_)
        );

        assert_matches!(
            Rpc::Write {
                key: "hello",
                value: 42
            }
            .allowed_by_attenuation(&RpcAtt::ReadWrite),
            Ok(_)
        );
    }

    #[test]
    fn test_rcan_encoding() -> TestResult {
        let issuer = SigningKey::from_bytes(&[0u8; 32]);
        let audience = SigningKey::from_bytes(&[1u8; 32]);
        let rcan = Rcan::builder(&issuer, audience.verifying_key())
            .issuing(RpcAtt::ReadWrite)
            .sign(Expires::Never);

        println!("{}", hex::encode(rcan.encode()));
        assert_eq!(hex::encode(rcan.encode()), "01203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01203b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da290100cede73ce610c4196671a60335beca23464f06cbc9402bf1c9b7377e36453c43d2652fd2c857fab4300fa92da6ea357435c341123ef89d189884e56f58ce88206");
        assert_eq!(Rcan::decode(&rcan.encode())?, rcan);
        Ok(())
    }

    #[test]
    fn test_rcan_invocation() -> TestResult {
        let service = SigningKey::from_bytes(&[0u8; 32]);
        let alice = SigningKey::from_bytes(&[1u8; 32]);
        let bob = SigningKey::from_bytes(&[2u8; 32]);

        // The service gives alice access to everything for 60 seconds
        let service_rcan = Rcan::builder(&service, alice.verifying_key())
            .issuing(RpcAtt::All)
            .sign(Expires::valid_for(Duration::from_secs(60)));
        // alice gives attenuated (only read access) to bob, but doesn't care for how long still
        let friend_rcan = Rcan::builder(&alice, bob.verifying_key())
            .delegating(service.verifying_key(), RpcAtt::Read)
            .sign(Expires::Never);
        // bob can now pass the authorization test for the service
        let service_auth = Authorizer::new(service.verifying_key());
        assert_matches!(
            service_auth.check_invocation_from(
                bob.verifying_key(),
                Rpc::Read { key: "secrets" },
                &[&service_rcan, &friend_rcan],
            ),
            Ok(_)
        );

        // but bob doesn't have read-write access
        assert_matches!(
            service_auth.check_invocation_from(
                bob.verifying_key(),
                Rpc::Write {
                    key: "secret",
                    value: 1337
                },
                &[&service_rcan, &friend_rcan]
            ),
            Err(_)
        );

        Ok(())
    }
}
