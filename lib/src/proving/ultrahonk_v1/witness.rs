use alloy::primitives::Address;
use ark_bn254::Fr as Fr254;
use ark_ec::twisted_edwards::Affine as TEAffine;
use ark_ff::{BigInteger, PrimeField, Zero};
use jf_primitives::{
    poseidon::{FieldHasher, Poseidon},
    trees::{Directions, MembershipProof},
};
use nf_curves::ed_on_bn254::{BabyJubjub, Fr as BJJScalar};
use num_bigint::BigUint;
use serde_json::{Value, json};
use std::fmt;

use crate::derive_key::PRIVATE_KEY_PREFIX;
use crate::nf_client_proof::{PrivateInputs, PublicInputs};
use crate::shared_entities::DepositData;

#[derive(Debug)]
pub enum WitnessError {
    InvalidPrivateKeyPrefix,
    InvalidEphemeralKey(String),
    Poseidon(String),
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::InvalidPrivateKeyPrefix => write!(f, "invalid PRIVATE_KEY_PREFIX"),
            WitnessError::InvalidEphemeralKey(detail) => {
                write!(f, "invalid ephemeral BabyJubjub scalar: {detail}")
            }
            WitnessError::Poseidon(e) => write!(f, "Poseidon hash failed: {e}"),
        }
    }
}

impl std::error::Error for WitnessError {}

pub fn build_statement_inputs_json(
    private_inputs: &PrivateInputs,
    public_inputs: &PublicInputs,
) -> Result<Value, WitnessError> {
    let (zkp_priv, zkp_priv_lambda) = zkp_private_key_witness(private_inputs.root_key)?;
    let deposit_token_ids = map_deposits(&private_inputs.deposit_data, |d| d.nf_token_id);
    let deposit_slot_ids = map_deposits(&private_inputs.deposit_data, |d| d.nf_slot_id);
    let deposit_values = map_deposits(&private_inputs.deposit_data, |d| d.value);
    let deposit_secret_hashes = map_deposits(&private_inputs.deposit_data, |d| d.secret_hash);

    // M5 (fail-closed): the ephemeral scalar must be an in-range BabyJubjub
    // subgroup element, and non-zero only when consumed by a transfer's
    // recipient encryption. Deposits (`nullifiers_salts[0] == 0`) and
    // withdrawals (`withdraw_address != 0`) carry a sound zero ephemeral. This
    // mirrors the circuit's conditional `ephemeral != 0` assert.
    let is_deposit = private_inputs.nullifiers_salts[0].is_zero();
    let is_withdraw = !private_inputs.withdraw_address.is_zero();
    let encrypts_to_recipient = !is_deposit && !is_withdraw;
    validate_ephemeral_key(private_inputs.ephemeral_key, encrypts_to_recipient)?;
    let ephemeral_key = private_inputs.ephemeral_key;

    Ok(json!({
        "root": field_to_decimal(&public_inputs.root),
        "rootKey": field_to_decimal(&private_inputs.root_key),
        "zkpPriv": field_to_decimal(&zkp_priv),
        "zkpPrivLambda": field_to_decimal(&zkp_priv_lambda),
        "ephemeralKey": field_to_decimal(&ephemeral_key),
        "feeTokenId": field_to_decimal(&private_inputs.fee_token_id),
        "fee": field_to_decimal(&public_inputs.fee),
        "nfAddress": field_to_decimal(&address_to_fr(private_inputs.nf_address)),
        "nfSlotId": field_to_decimal(&private_inputs.nf_slot_id),
        "nullifiersValues": fr_array_to_decimal(&private_inputs.nullifiers_values),
        "nullifiersSalts": fr_array_to_decimal(&private_inputs.nullifiers_salts),
        "publicKeys": private_inputs.public_keys.iter().map(point_to_json).collect::<Vec<_>>(),
        "membershipProofs": private_inputs.membership_proofs.iter().map(membership_proof_to_json).collect::<Vec<_>>(),
        "secretPreimages": private_inputs.secret_preimages.iter().map(|row| fr_array_to_decimal(row)).collect::<Vec<_>>(),
        "commitmentsValues": fr_array_to_decimal(&private_inputs.commitments_values),
        "senderCommitmentSalts": fr_array_to_decimal(&private_inputs.sender_commitment_salts),
        "depositTokenIds": fr_array_to_decimal(&deposit_token_ids),
        "depositSlotIds": fr_array_to_decimal(&deposit_slot_ids),
        "depositValues": fr_array_to_decimal(&deposit_values),
        "depositSecretHashes": fr_array_to_decimal(&deposit_secret_hashes),
        "withdrawAddress": field_to_decimal(&private_inputs.withdraw_address),
        "partyAPublicKey": point_to_json(&private_inputs.party_a_public_key),
        "partyBPublicKey": point_to_json(&private_inputs.party_b_public_key),
        "nfTokenAId": field_to_decimal(&private_inputs.nf_token_a_id),
        "valueA": field_to_decimal(&private_inputs.value_a),
        "nfTokenBId": field_to_decimal(&private_inputs.nf_token_b_id),
        "valueB": field_to_decimal(&private_inputs.value_b),
        "swapNonce": field_to_decimal(&private_inputs.swap_nonce),
        "deadline": field_to_decimal(&private_inputs.deadline),
    }))
}

pub fn zkp_private_key_witness(root_key: Fr254) -> Result<(BJJScalar, Fr254), WitnessError> {
    let poseidon: Poseidon<Fr254> = Poseidon::new();
    let prefix = BigUint::parse_bytes(PRIVATE_KEY_PREFIX.as_bytes(), 10)
        .map(Fr254::from)
        .ok_or(WitnessError::InvalidPrivateKeyPrefix)?;
    let hash = poseidon
        .hash(&[root_key, prefix])
        .map_err(|e| WitnessError::Poseidon(format!("{e:?}")))?;
    let scalar = BJJScalar::from_be_bytes_mod_order(&hash.into_bigint().to_bytes_be());

    let hash_big = BigUint::from_bytes_be(&hash.into_bigint().to_bytes_be());
    let scalar_big = BigUint::from_bytes_be(&scalar.into_bigint().to_bytes_be());
    let subgroup_order = BigUint::from_bytes_be(&<BJJScalar as PrimeField>::MODULUS.to_bytes_be());
    let lambda_big = (&hash_big - &scalar_big) / &subgroup_order;
    let lambda = Fr254::from_le_bytes_mod_order(&lambda_big.to_bytes_le());

    Ok((scalar, lambda))
}

fn validate_ephemeral_key(
    ephemeral_key: Fr254,
    require_non_zero: bool,
) -> Result<(), WitnessError> {
    if require_non_zero && ephemeral_key.is_zero() {
        return Err(WitnessError::InvalidEphemeralKey(
            "zero scalar is rejected by the UltraHonk statement circuit for transfers"
                .to_string(),
        ));
    }

    let value = field_to_biguint(&ephemeral_key);
    let subgroup_order = field_modulus_biguint::<BJJScalar>();
    if value >= subgroup_order {
        return Err(WitnessError::InvalidEphemeralKey(
            "scalar is outside the BabyJubjub subgroup range".to_string(),
        ));
    }

    Ok(())
}

fn field_modulus_biguint<F: PrimeField>() -> BigUint {
    BigUint::from_bytes_be(&F::MODULUS.to_bytes_be())
}

fn field_to_biguint<F: PrimeField>(value: &F) -> BigUint {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be())
}

pub(crate) fn field_to_decimal<F: PrimeField>(value: &F) -> String {
    field_to_biguint(value).to_str_radix(10)
}

fn fr_array_to_decimal<const N: usize>(values: &[Fr254; N]) -> Vec<String> {
    values.iter().map(field_to_decimal).collect()
}

fn map_deposits<F>(deposit_data: &[DepositData; 4], f: F) -> [Fr254; 4]
where
    F: Fn(&DepositData) -> Fr254,
{
    std::array::from_fn(|i| f(&deposit_data[i]))
}

fn address_to_fr(address: Address) -> Fr254 {
    Fr254::from(BigUint::from_bytes_be(address.as_slice()))
}

fn point_to_json(point: &TEAffine<BabyJubjub>) -> Value {
    json!({
        "x": field_to_decimal(&point.x),
        "y": field_to_decimal(&point.y),
    })
}

fn membership_proof_to_json(proof: &MembershipProof<Fr254>) -> Value {
    json!(
        proof
            .sibling_path
            .iter()
            .map(|path| json!({
                "sibling": field_to_decimal(&path.value),
                "siblingOnLeft": matches!(path.direction, Directions::HashWithThisNodeOnLeft),
            }))
            .collect::<Vec<_>>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{One, Zero};

    #[test]
    fn statement_inputs_json_has_sidecar_contract_fields() {
        let mut private_inputs = PrivateInputs::default();
        private_inputs.ephemeral_key = Fr254::one();
        let public_inputs = PublicInputs::default();
        let value = build_statement_inputs_json(&private_inputs, &public_inputs).unwrap();

        for field in [
            "root",
            "rootKey",
            "zkpPriv",
            "zkpPrivLambda",
            "ephemeralKey",
            "feeTokenId",
            "fee",
            "nfAddress",
            "nfSlotId",
            "nullifiersValues",
            "nullifiersSalts",
            "publicKeys",
            "membershipProofs",
            "secretPreimages",
            "commitmentsValues",
            "senderCommitmentSalts",
            "depositTokenIds",
            "depositSlotIds",
            "depositValues",
            "depositSecretHashes",
            "withdrawAddress",
            "partyAPublicKey",
            "partyBPublicKey",
            "nfTokenAId",
            "valueA",
            "nfTokenBId",
            "valueB",
            "swapNonce",
            "deadline",
        ] {
            assert!(value.get(field).is_some(), "missing {field}");
        }

        assert_eq!(value["membershipProofs"][0].as_array().unwrap().len(), 32);
        assert_eq!(value["membershipProofs"][0][0]["siblingOnLeft"], true);
        assert_eq!(value["depositValues"][0], field_to_decimal(&Fr254::zero()));
    }

    #[test]
    fn transfer_zero_or_out_of_range_ephemeral_key_is_rejected_fail_closed() {
        // A transfer (non-deposit, non-withdraw) consumes the ephemeral scalar
        // for recipient encryption, so a zero or out-of-range ephemeral must be
        // rejected fail-closed, matching the circuit's conditional assert.
        let mut private_inputs = PrivateInputs::default();
        private_inputs.nullifiers_salts[0] = Fr254::one(); // non-deposit
        assert!(private_inputs.withdraw_address.is_zero()); // non-withdraw
        assert!(private_inputs.ephemeral_key.is_zero());
        assert!(matches!(
            build_statement_inputs_json(&private_inputs, &PublicInputs::default()),
            Err(WitnessError::InvalidEphemeralKey(_))
        ));

        private_inputs.ephemeral_key = Fr254::from(field_modulus_biguint::<BJJScalar>());
        assert!(matches!(
            build_statement_inputs_json(&private_inputs, &PublicInputs::default()),
            Err(WitnessError::InvalidEphemeralKey(_))
        ));
    }

    #[test]
    fn deposit_and_withdraw_accept_zero_ephemeral_key() {
        // Deposits and withdrawals publish ephemeral-independent data, so the
        // circuit does not require a non-zero ephemeral. The witness builder
        // must therefore accept the honest zero ephemeral on those paths.
        let deposit_data = [DepositData::default(); 4];
        let deposit_inputs = PrivateInputs::for_deposit(&deposit_data);
        assert!(deposit_inputs.ephemeral_key.is_zero());
        assert!(
            build_statement_inputs_json(&deposit_inputs, &PublicInputs::for_deposit()).is_ok()
        );

        // Withdraw shape: non-deposit (salt set) + withdraw_address != 0.
        let mut withdraw_inputs = PrivateInputs::default();
        withdraw_inputs.nullifiers_salts[0] = Fr254::one();
        withdraw_inputs.withdraw_address = Fr254::from(0x1234u64);
        assert!(withdraw_inputs.ephemeral_key.is_zero());
        assert!(
            build_statement_inputs_json(&withdraw_inputs, &PublicInputs::default()).is_ok()
        );
    }

    #[test]
    fn out_of_range_ephemeral_key_is_rejected_even_for_deposit() {
        // The subgroup range check is unconditional; only the non-zero check is
        // mode-scoped. An out-of-range ephemeral must fail even on a deposit.
        let deposit_data = [DepositData::default(); 4];
        let mut deposit_inputs = PrivateInputs::for_deposit(&deposit_data);
        deposit_inputs.ephemeral_key = Fr254::from(field_modulus_biguint::<BJJScalar>());
        assert!(matches!(
            build_statement_inputs_json(&deposit_inputs, &PublicInputs::for_deposit()),
            Err(WitnessError::InvalidEphemeralKey(_))
        ));
    }

    #[test]
    fn valid_ephemeral_key_is_preserved() {
        let mut private_inputs = PrivateInputs::default();
        private_inputs.ephemeral_key = Fr254::from(555555u64);
        let value = build_statement_inputs_json(&private_inputs, &PublicInputs::default()).unwrap();
        assert_eq!(
            value["ephemeralKey"],
            field_to_decimal(&Fr254::from(555555u64))
        );
    }
}
