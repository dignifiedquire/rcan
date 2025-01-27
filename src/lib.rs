use std::cmp::Ordering;
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
/// A cap can be delgated, if we can compare it to another one
/// `cap_a <= cap_b` means that `cap_a` is a subset or equal of `cap_b`
/// which would allow a delegation.
pub trait Delegatable: Capability + PartialOrd {
    fn can_delegate_to_us(&self, other: &Self) -> bool {
        matches!(
            self.partial_cmp(other),
            Some(Ordering::Less) | Some(Ordering::Equal)
        )
    }
}

impl<C: Capability + PartialOrd> Delegatable for C {}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Caps<C: Capability = ()>(
    #[serde(bound = "C: Capability")] BTreeMap<VerifyingKeyWrapper, C>,
);

impl<C: Capability> Default for Caps<C> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

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

    pub fn from_payload(issuer: &SigningKey, payload: Payload<C>) -> Result<Self> {
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

        // verify caps
        for (cap_root, cap) in rcan.payload.caps.iter() {
            if cap_root == &rcan.payload.issuer {
                // simple case, issuer can issuer any cap
            } else {
                anyhow::bail!(
                    "invalid delegation: {} -> {:?}",
                    hex::encode(cap_root.as_bytes()),
                    cap
                );
            }
        }
        Ok(rcan)
    }
}

impl<C: Delegatable> Rcan<C> {
    pub fn delegate<R: Rng + CryptoRng>(
        &self,
        mut rng: R,
        issuer: &SigningKey,
        audience: VerifyingKey,
        cap_root: VerifyingKey,
        cap: C,
    ) -> Result<Self> {
        let Some(source_cap) = self.payload.caps.get(&cap_root) else {
            anyhow::bail!("cap is not available");
        };
        if !cap.can_delegate_to_us(source_cap) {
            anyhow::bail!("cannot delegate: not allowed");
        }

        let mut caps = Caps::<C>::default();
        caps.insert(cap_root, cap);

        let nonce: [u8; NONCE_SIZE] = rng.gen();
        let payload = Payload {
            issuer: issuer.verifying_key(),
            nonce,
            audience,
            caps,
            valid_until: None,
        };

        Self::from_payload(issuer, payload)
    }

    pub fn decode_with_time_and_chain(
        bytes: &[u8],
        now: u64,
        delegation_chain: &[&Rcan<C>],
    ) -> Result<Self> {
        let rcan: Rcan<C> = postcard::from_bytes(bytes).context("encoding")?;
        ensure!(rcan.version == VERSION, "invalid version: {}", rcan.version);
        rcan.payload
            .issuer
            .verify_strict(&bytes[PAYLOAD_OFFSET..], &rcan.signature)?;

        if let Some(valid_until) = rcan.payload.valid_until {
            ensure!(now <= valid_until, "expired");
        }

        // verify caps
        for (cap_root, cap) in rcan.payload.caps.iter() {
            if cap_root == &rcan.payload.issuer {
                // simple case, issuer can issue any cap
            } else {
                let mut last_parent = &rcan;
                let mut smallest_cap = cap;

                loop {
                    if let Some((parent, parent_cap)) =
                        find_parent(last_parent, cap_root, delegation_chain)
                    {
                        if &parent.payload.issuer == cap_root {
                            // we have hit the end of the chain, done
                            break;
                        } else {
                            last_parent = parent;
                            if smallest_cap > parent_cap {
                                smallest_cap = parent_cap;
                            };
                        }
                    } else {
                        anyhow::bail!(
                            "missing delegation chain elements for {:?}: {:?}",
                            hex::encode(cap_root.as_bytes()),
                            cap
                        );
                    }
                }

                // make sure the smallest cap is enough to satisfy our cap
                ensure!(cap.can_delegate_to_us(smallest_cap), "no valid cap found");
            }
        }

        Ok(rcan)
    }
}

fn find_parent<'a, C: Delegatable>(
    rcan: &Rcan<C>,
    cap_root: &VerifyingKey,
    delegation_chain: &[&'a Rcan<C>],
) -> Option<(&'a Rcan<C>, &'a C)> {
    delegation_chain
        .iter()
        .filter_map(|other| {
            if other.payload.audience == rcan.payload.issuer {
                other.payload.caps.get(cap_root).map(|c| (*other, c))
            } else {
                None
            }
        })
        .next()
}

/// Returns the unix epoch seconds for the current time.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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

    // Two capabilities:
    // api: none, read, write
    // app: none, read, write

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
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

    impl PartialOrd for MyCap {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            use std::cmp::Ordering::*;

            let this_api = self.api();
            let this_app = self.app();

            let other_api = other.api();
            let other_app = other.app();

            match (this_api.cmp(&other_api), this_app.cmp(&other_app)) {
                (Less, Less) => Some(Less),
                (Less, Equal) => Some(Less),
                (Less, Greater) => None,
                (Greater, Greater) => Some(Greater),
                (Greater, Less) => None,
                (Greater, Equal) => Some(Greater),
                (Equal, Equal) => Some(Equal),
                (Equal, Less) => Some(Less),
                (Equal, Greater) => Some(Greater),
            }
        }
    }

    #[test]
    fn test_delegate() {
        let a = MyCapBuilder::new().with_api(CapState::Read).build();
        let b = MyCapBuilder::new().with_api(CapState::Write).build();

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        assert_eq!(a.partial_cmp(&a), Some(Ordering::Equal));
        assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));

        let a = MyCapBuilder::new()
            .with_api(CapState::Read)
            .with_app(CapState::Write)
            .build();
        let b = MyCapBuilder::new()
            .with_api(CapState::Write)
            .with_app(CapState::Write)
            .build();

        assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
        assert!(a.can_delegate_to_us(&b));

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        // Delegate from root_issuer -> receiver_1 -> receiver_2

        let root_issuer = SigningKey::generate(&mut rng);
        let receiver_1 = SigningKey::generate(&mut rng);
        let receiver_2 = SigningKey::generate(&mut rng);

        let mut caps = Caps::<MyCap>::default();

        // The root_issuer delegates these caps to receiver_1
        let write_app_read_api_cap = MyCapBuilder::new()
            .with_api(CapState::Read)
            .with_app(CapState::Write)
            .build();
        caps.insert(root_issuer.verifying_key(), write_app_read_api_cap);

        let rcan_1 = Rcan::new(&mut rng, &root_issuer, receiver_1.verifying_key(), caps);
        {
            let encoded = rcan_1.encode_to_bytes();
            let decoded = Rcan::decode(&encoded).expect("failed to verify");
            assert_eq!(rcan_1, decoded);
        }

        // receiver_1 delegates this to receiver_2
        let read_app_read_api_cap = MyCapBuilder::new()
            .with_api(CapState::Read)
            .with_app(CapState::Read)
            .build();

        let rcan_2 = rcan_1
            .delegate(
                &mut rng,
                &receiver_1,
                receiver_2.verifying_key(),
                root_issuer.verifying_key(),
                read_app_read_api_cap,
            )
            .expect("failed to delegate");
        {
            let encoded = rcan_2.encode_to_bytes();
            let err = Rcan::<MyCap>::decode(&encoded).unwrap_err();
            assert!(err.to_string().contains("invalid delegation"));

            let decoded = Rcan::decode_with_time_and_chain(&encoded, now(), &[&rcan_1])
                .expect("invalid delegation");
            assert_eq!(decoded, rcan_2);
        }
    }

    #[test]
    fn test_simple_caps() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let issuer = SigningKey::generate(&mut rng);
        let receiver = SigningKey::generate(&mut rng);

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

        assert!(MyCapBuilder::new()
            .with_api(CapState::Read)
            .build()
            .can_delegate_to_us(&MyCapBuilder::new().with_api(CapState::Read).build()));

        assert!(MyCapBuilder::new()
            .with_api(CapState::Read)
            .build()
            .can_delegate_to_us(&MyCapBuilder::new().with_api(CapState::Write).build()));
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
