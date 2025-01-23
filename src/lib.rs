use std::collections::BTreeMap;
use std::time::SystemTime;

// TODO: better error management
use anyhow::{ensure, Context, Result};
use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::{CryptoRng, Rng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// TODO: what's the smalles secure value?
pub const NONCE_SIZE: usize = 12;

pub const VERSION: u8 = 1;

pub trait Capability:
    std::fmt::Debug + Sized + Serialize + DeserializeOwned + PartialEq + Eq + Clone
{
}

impl<T: std::fmt::Debug + Sized + Serialize + DeserializeOwned + PartialEq + Eq + Clone> Capability
    for T
{
}

/// Returns the unix epoch seconds for the current time.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct Caps<C: Capability = ()>(
    #[serde(bound = "C: Capability")] BTreeMap<VerifyingKeyWrapper, C>,
);

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

impl<C: Capability> Caps<C> {
    pub fn insert(&mut self, key: VerifyingKey, cap: C) {
        self.0.insert(VerifyingKeyWrapper(key), cap);
    }

    pub fn get(&self, key: &VerifyingKey) -> Option<&C> {
        self.0.get(&VerifyingKeyWrapper(*key))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&VerifyingKey, &C)> {
        self.0.iter().map(|(k, c)| (&k.0, c))
    }
}

#[derive(Clone, Serialize, Deserialize, derive_more::Debug, PartialEq, Eq)]
pub struct Payload<C: Capability> {
    /// The issuer
    #[debug("{}", hex::encode(issuer))]
    issuer: VerifyingKey,
    /// The intended audience
    #[debug("{}", hex::encode(audience))]
    audience: VerifyingKey,
    /// Nonce, to avoid replayability.
    #[debug("{}", hex::encode(nonce))]
    nonce: [u8; NONCE_SIZE],
    /// Capabilities
    #[serde(bound = "C: Capability")]
    caps: Caps<C>,
    /// Valid until unix timestamp in seconds.
    valid_until: Option<u64>,
}

impl<C: Capability> Payload<C> {
    pub fn new<R: Rng + CryptoRng>(
        mut rng: R,
        issuer: VerifyingKey,
        audience: VerifyingKey,
        caps: Caps<C>,
    ) -> Self {
        let nonce: [u8; NONCE_SIZE] = rng.gen();

        Self {
            issuer,
            audience,
            nonce,
            caps,
            valid_until: None,
        }
    }

    pub fn set_valid_until(&mut self, valid_until: u64) {
        self.valid_until.replace(valid_until);
    }

    pub fn encode_to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("vec")
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Rcan<C: Capability> {
    /// The version number.
    version: u8,
    /// Signature over the serialized payload.
    signature: Signature,
    /// The actaul content.
    #[serde(bound = "C: Capability")]
    payload: Payload<C>,
}

/// offset into a serialized version to the payload
const PAYLOAD_OFFSET: usize = 1 + Signature::BYTE_SIZE;

impl<C: Capability> Rcan<C> {
    pub fn new<R: Rng + CryptoRng>(
        mut rng: R,
        issuer: &SigningKey,
        audience: VerifyingKey,
        caps: Caps<C>,
    ) -> Self {
        let payload = Payload::new(&mut rng, issuer.verifying_key(), audience, caps);
        let payload_ser = payload.encode_to_bytes();

        let signature = issuer.sign(&payload_ser);

        Self {
            version: VERSION,
            signature,
            payload,
        }
    }

    pub fn new_with_expiry<R: Rng + CryptoRng>(
        mut rng: R,
        issuer: &SigningKey,
        audience: VerifyingKey,
        caps: Caps<C>,
        valid_until: u64,
    ) -> Self {
        let mut payload = Payload::new(&mut rng, issuer.verifying_key(), audience, caps);
        payload.set_valid_until(valid_until);

        let payload_ser = payload.encode_to_bytes();
        let signature = issuer.sign(&payload_ser);

        Self {
            version: VERSION,
            signature,
            payload,
        }
    }

    pub fn from_payload(issuer: &mut SigningKey, payload: Payload<C>) -> Result<Self> {
        ensure!(issuer.verifying_key() == payload.issuer, "issuer missmatch");
        let payload_ser = payload.encode_to_bytes();
        let signature = issuer.sign(&payload_ser);

        Ok(Self {
            version: VERSION,
            signature,
            payload,
        })
    }

    pub fn encode_to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("vec")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_with_time(bytes, now())
    }

    pub fn decode_with_time(bytes: &[u8], now: u64) -> Result<Self> {
        let rcan: Rcan<C> = postcard::from_bytes(bytes).context("encoding")?;
        ensure!(rcan.version == VERSION, "invalid version: {}", rcan.version);
        rcan.payload
            .issuer
            .verify_strict(&bytes[PAYLOAD_OFFSET..], &rcan.signature)?;

        if let Some(valid_until) = rcan.payload.valid_until {
            ensure!(now <= valid_until, "expired");
        }

        Ok(rcan)
    }
}

// impl<C: C Payload {
//     pub fn delegate<R: Rng + CryptoRng, S: CapSelector>(
//         &self,
//         mut rng: R,
//         issuer: &VerifyingKey,
//         audience: &VerifyingKey,
//         selector: S,
//     ) -> Result<Payload> {
//         let mut caps = Caps::default();
//         for (cap_root, cap) in self.caps.iter() {
//             if let Some(new_cap) = selector.select(cap_root, cap) {
//                 caps.insert(*cap_root, new_cap);
//             }
//         }

//         let nonce: [u8; NONCE_SIZE] = rng.gen();

//         Ok(Payload {
//             issuer: issuer.clone(),
//             nonce,
//             audience: audience.clone(),
//             caps,
//             valid_until: None,
//         })
//     }
// }
//
// pub trait CapSelector {
//     /// Returns a selection of the provided caps
//     fn select(&self, source: &VerifyingKey, cap: &Cap) -> Option<Cap>;
// }

#[cfg(test)]
mod tests {
    use bitfields::bitfield;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    fn test_basics() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let issuer = SigningKey::generate(&mut rng);
        let receiver = SigningKey::generate(&mut rng);

        let caps = Caps::<()>::default();
        let rcan = Rcan::new(&mut rng, &issuer, receiver.verifying_key(), caps);

        let encoded = rcan.encode_to_bytes();
        let decoded = Rcan::decode(&encoded).expect("failed to verify");
        assert_eq!(rcan, decoded);
    }

    #[test]
    fn test_simple_caps() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let issuer = SigningKey::generate(&mut rng);
        let receiver = SigningKey::generate(&mut rng);

        // Two capabilities:
        // api: none, read, write
        // app: none, read, write

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[repr(u8)]
        enum CapState {
            None = 0,
            Read = 1,
            Write = 2,
        }

        impl CapState {
            const fn from_bits(bits: u8) -> Self {
                match bits {
                    0 => Self::None,
                    1 => Self::Read,
                    2 => Self::Write,
                    _ => Self::Write, // safe default for higher values
                }
            }

            const fn into_bits(self) -> u8 {
                self as u8
            }
        }

        // Caps get encoded into a bit vector
        // 3 states per cap, so we need 2 bits per cap
        #[bitfield(u8)]
        #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
        struct MyCap {
            #[bits(2)]
            api: CapState,
            #[bits(2)]
            app: CapState,
            /// Unused for now
            #[bits(4)]
            _padding: u8,
        }

        let mut caps = Caps::<MyCap>::default();

        // The issuer delegates these caps
        let write_app_read_api_cap = MyCapBuilder::new()
            .with_api(CapState::Read)
            .with_app(CapState::Write)
            .build();
        caps.insert(issuer.verifying_key(), write_app_read_api_cap);

        let rcan = Rcan::new(&mut rng, &issuer, receiver.verifying_key(), caps);

        let encoded = rcan.encode_to_bytes();
        let decoded = Rcan::decode(&encoded).expect("failed to verify");

        assert_eq!(rcan, decoded);
    }

    #[test]
    fn test_expired() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let issuer = SigningKey::generate(&mut rng);
        let receiver = SigningKey::generate(&mut rng);

        let caps = Caps::<()>::default();
        let now = now();

        let rcan =
            Rcan::new_with_expiry(&mut rng, &issuer, receiver.verifying_key(), caps, now + 1);

        let encoded = rcan.encode_to_bytes();

        // valid
        let _ = Rcan::<()>::decode_with_time(&encoded, now).expect("should verify");

        // expired
        let err = Rcan::<()>::decode_with_time(&encoded, now + 3).unwrap_err();
        assert!(err.to_string().contains("expired"), "{}", err);
    }

    #[test]
    fn test_payload_roundtrip() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let issuer = SigningKey::generate(&mut rng);
        let receiver = SigningKey::generate(&mut rng);

        let caps = Caps::<()>::default();
        let mut payload = Payload::new(
            &mut rng,
            issuer.verifying_key(),
            receiver.verifying_key(),
            caps,
        );

        payload.set_valid_until(now());

        let encoded = payload.encode_to_bytes();
        let decoded = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(payload, decoded);
    }
}
