use alloy::primitives::Bytes;
use ark_bn254::Fr as Fr254;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::SerializationError;
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::nf_client_proof::Proof;
use crate::proving::ProofSystemId;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UltraHonkProof {
    pub proof: Vec<u8>,
    #[serde(
        serialize_with = "serialize_fr_vec_decimal",
        deserialize_with = "deserialize_fr_vec_decimal"
    )]
    pub public_inputs: Vec<Fr254>,
}

impl Proof for UltraHonkProof {
    fn compress_proof(&self) -> Result<Bytes, SerializationError> {
        let bytes = bincode::serialize(self).map_err(|_| SerializationError::InvalidData)?;
        Ok(Bytes::from(bytes))
    }

    fn from_compressed(compressed: Bytes) -> Result<Self, SerializationError>
    where
        Self: Sized,
    {
        bincode::deserialize::<Self>(&compressed).map_err(|_| SerializationError::InvalidData)
    }

    fn system_id() -> ProofSystemId {
        ProofSystemId::UltraHonkV1
    }

    fn to_wire_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = vec![ProofSystemId::UltraHonkV1 as u8];
        bytes.extend_from_slice(&self.compress_proof()?);
        Ok(bytes)
    }
}

fn fr_to_decimal(value: &Fr254) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn fr_from_decimal(value: &str) -> Result<Fr254, String> {
    let bigint = BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| format!("invalid decimal field element: {value}"))?;
    Ok(Fr254::from(bigint))
}

fn serialize_fr_vec_decimal<S>(values: &[Fr254], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let strings: Vec<String> = values.iter().map(fr_to_decimal).collect();
    strings.serialize(serializer)
}

fn deserialize_fr_vec_decimal<'de, D>(deserializer: D) -> Result<Vec<Fr254>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings = Vec::<String>::deserialize(deserializer)?;
    strings
        .iter()
        .map(|value| fr_from_decimal(value).map_err(serde::de::Error::custom))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{One, Zero};

    #[test]
    fn compressed_roundtrip_preserves_public_inputs() {
        let proof = UltraHonkProof {
            proof: vec![1, 2, 3, 4],
            public_inputs: vec![Fr254::zero(), Fr254::one()],
        };

        let compressed = proof.compress_proof().unwrap();
        let restored = UltraHonkProof::from_compressed(compressed).unwrap();
        assert_eq!(restored.proof, proof.proof);
        assert_eq!(restored.public_inputs, proof.public_inputs);
    }

    #[test]
    fn wire_bytes_are_prefixed_with_system_id() {
        let proof = UltraHonkProof::default();
        let bytes = proof.to_wire_bytes().unwrap();
        assert_eq!(bytes[0], ProofSystemId::UltraHonkV1 as u8);
    }
}
