//! Parity test: the native reference must reproduce the frozen Nightfish vectors.
//!
//! These are the same constants asserted in-circuit by `../noir/src/tests.nr`,
//! so Rust ⇄ Noir agreement is anchored to one shared vector set. The formulas
//! are nf4's **real** gadgets (derived keys, arity-6 commitment, 3-field KEM-DEM,
//! arity-4 deposit nullifier key).

use nightfish_honk_ref::{bjj_to_dec, compute_client, fr_to_dec, reference_inputs};

const ZKP_PRIV: &str =
    "2669394594254500456919567884988224373346673904535463713340572478167716603703";
const PK_X: &str = "15104287708573421274381189464382717686045733043453322610710351834809440917570";
const PK_Y: &str = "20954351963592359756230058488404580197532105722342534281851194307785105336248";
const SS_X: &str = "21394224457779945146846288446080159182116964126833871581201419943354276141150";
const SS_Y: &str = "10039833070770417257460196453726795431614617701371074717866201713583548899881";
const EPK_X: &str = "5325907528513884424380017726062308565928797621566528782280251082751367394195";
const EPK_Y: &str = "10697004986745323395179375080111610621714274545583785017977698611729250111567";
const ENC_KEY: &str =
    "17056245747906735152001062717029652415839628306060084987928820896766327738093";
const CIPHER0: &str =
    "20396195620446049940804390200318847988622350684759135854695482041293222382078";
const CIPHER1: &str =
    "3492188594155931727114175353668522501752588642535634162826830209466713360773";
const CIPHER2: &str = "393278284149491041187611192774030390409580250993399288969475731507412034194";
const X_PARITY: &str = "0";
const SALT: &str = "10039833070770417257460196453726795431614617701371074717866201713583548899881";
const COMMITMENT: &str =
    "13168301755547694436234202734676261256754151368150229644929714876727700148853";
const NULL_KEY: &str =
    "20477464649897077618197549574668945360958836136043147071491435722036752052453";
const NULLIFIER: &str =
    "6911201607930511352194694757154219304469727562960252579393956685715601091129";
const DEPOSIT_NULL_KEY: &str =
    "17949589916702792243286835327245960780740389215658310900126994280577928576185";

#[test]
fn reference_matches_frozen_vectors() {
    let t = compute_client(&reference_inputs());
    assert_eq!(bjj_to_dec(&t.zkp_priv), ZKP_PRIV, "zkp_priv");
    assert_eq!(fr_to_dec(&t.pk.x), PK_X, "pk.x");
    assert_eq!(fr_to_dec(&t.pk.y), PK_Y, "pk.y");
    assert_eq!(fr_to_dec(&t.ss.x), SS_X, "ss.x");
    assert_eq!(fr_to_dec(&t.ss.y), SS_Y, "ss.y");
    assert_eq!(fr_to_dec(&t.epk.x), EPK_X, "epk.x");
    assert_eq!(fr_to_dec(&t.epk.y), EPK_Y, "epk.y");
    assert_eq!(fr_to_dec(&t.enc_key), ENC_KEY, "enc_key");
    assert_eq!(fr_to_dec(&t.ciphers[0]), CIPHER0, "cipher0");
    assert_eq!(fr_to_dec(&t.ciphers[1]), CIPHER1, "cipher1");
    assert_eq!(fr_to_dec(&t.ciphers[2]), CIPHER2, "cipher2");
    assert_eq!(fr_to_dec(&t.x_parity), X_PARITY, "x_parity");
    assert_eq!(fr_to_dec(&t.salt), SALT, "salt");
    assert_eq!(fr_to_dec(&t.commitment), COMMITMENT, "commitment");
    assert_eq!(fr_to_dec(&t.null_key), NULL_KEY, "null_key");
    assert_eq!(fr_to_dec(&t.nullifier), NULLIFIER, "nullifier");
    assert_eq!(
        fr_to_dec(&t.deposit_null_key),
        DEPOSIT_NULL_KEY,
        "deposit_null_key"
    );

    // compressed_secrets = [c0, c1, c2, epk.y, x_parity]
    assert_eq!(fr_to_dec(&t.compressed_secrets[0]), CIPHER0);
    assert_eq!(fr_to_dec(&t.compressed_secrets[1]), CIPHER1);
    assert_eq!(fr_to_dec(&t.compressed_secrets[2]), CIPHER2);
    assert_eq!(fr_to_dec(&t.compressed_secrets[3]), EPK_Y);
    assert_eq!(fr_to_dec(&t.compressed_secrets[4]), X_PARITY);
}

#[test]
fn reference_points_are_on_curve_and_in_subgroup() {
    let t = compute_client(&reference_inputs());
    for p in [t.pk, t.ss, t.epk] {
        assert!(p.is_on_curve(), "point not on curve");
        assert!(
            p.is_in_correct_subgroup_assuming_on_curve(),
            "point not in prime-order subgroup"
        );
    }
}
