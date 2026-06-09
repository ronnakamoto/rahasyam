//! Baby JubJub — twisted Edwards `a = 1` form, matching `nf_curves::ed_on_bn254`.
//!
//! Parameters are reproduced from `nf-curves` and verified by reproducing the
//! Rust `k·G` test vectors (see `../rust` and `noir-bjj-parity`). The curve is
//!
//! ```text
//!   a·x² + y² = 1 + d·x²·y²       with a = 1
//! ```
//!
//! over the BN254 scalar field. Scalars live in the prime-order subgroup of order
//! `SUBGROUP_ORDER` (`≈ 2^251`).

/// Twisted-Edwards `a` coefficient.
pub global COEFF_A: Field = 1;
/// Twisted-Edwards `d` coefficient (`nf_curves::ed_on_bn254`).
pub global COEFF_D: Field =
    9706598848417545097372247223557719406784115219466060233080913168975159366771;
/// Generator x-coordinate.
pub global GENERATOR_X: Field =
    19698561148652590122159747500897617769866003486955115824547446575314762165298;
/// Generator y-coordinate.
pub global GENERATOR_Y: Field =
    19298250018296453272277890825869354524455968081175474282777126169995084727839;
/// Order of the prime-order subgroup (`nf_curves::ed_on_bn254::Fr` modulus).
pub global SUBGROUP_ORDER: Field =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;
/// Bit length used for double-and-add (subgroup order is `< 2^251`).
pub global SCALAR_BITS: u32 = 251;

/// An affine Baby JubJub point.
pub struct Point {
    pub x: Field,
    pub y: Field,
}

/// The fixed group generator `G`.
pub fn generator() -> Point {
    Point { x: GENERATOR_X, y: GENERATOR_Y }
}

/// The neutral element `(0, 1)`.
pub fn identity() -> Point {
    Point { x: 0, y: 1 }
}

/// Twisted-Edwards addition for `a = 1`:
/// `x3 = (x1·y2 + y1·x2) / (1 + d·x1·x2·y1·y2)`,
/// `y3 = (y1·y2 - x1·x2) / (1 - d·x1·x2·y1·y2)`.
pub fn add(p: Point, q: Point) -> Point {
    let x1x2 = p.x * q.x;
    let y1y2 = p.y * q.y;
    let x1y2 = p.x * q.y;
    let y1x2 = p.y * q.x;
    let dxy = COEFF_D * x1x2 * y1y2;
    Point { x: (x1y2 + y1x2) / (1 + dxy), y: (y1y2 - x1x2) / (1 - dxy) }
}

/// Point doubling.
pub fn double(p: Point) -> Point {
    add(p, p)
}

/// Variable-base scalar multiplication via LSB-first double-and-add.
/// Mirrors NF4's `variable_base_scalar_mul`. The scalar must fit in
/// [`SCALAR_BITS`] bits; use [`assert_valid_scalar`] to enforce subgroup membership.
pub fn scalar_mul(scalar: Field, base: Point) -> Point {
    let bits: [bool; SCALAR_BITS] = scalar.to_le_bits();
    let mut acc = identity();
    let mut cur = base;
    for i in 0..SCALAR_BITS {
        if bits[i] {
            acc = add(acc, cur);
        }
        cur = double(cur);
    }
    acc
}

/// Fixed-base multiplication of the generator: `scalar · G`.
pub fn mul_by_generator(scalar: Field) -> Point {
    scalar_mul(scalar, generator())
}

/// `true` iff `p` satisfies the curve equation `x² + y² = 1 + d·x²·y²`.
pub fn is_on_curve(p: Point) -> bool {
    let xx = p.x * p.x;
    let yy = p.y * p.y;
    (xx + yy) == (1 + COEFF_D * xx * yy)
}

/// Abort unless `p` is on the curve.
pub fn assert_on_curve(p: Point) {
    assert(is_on_curve(p), "bjj: point not on curve");
}

/// Abort unless `scalar` is a valid subgroup scalar, i.e. `0 <= scalar < l`.
///
/// This is the production-hardened check: the prototypes only bounded scalars to
/// 251 bits, which admits a few values `>= l`. A tight `< l` comparison removes
/// that ambiguity.
pub fn assert_valid_scalar(scalar: Field) {
    assert(scalar.lt(SUBGROUP_ORDER), "bjj: scalar out of subgroup range");
}

/// M3: assert that `p` is on the curve AND in the prime-order subgroup before it
/// is used as a Diffie-Hellman scalar-mul base (cofactor check `[l] * P == O`).
/// Without this an attacker could supply an off-curve or small-order point and
/// mount an invalid-curve / small-subgroup attack on the derived shared secret.
/// The neutral element passes both checks, so the withdraw/deposit (neutral
/// recipient) case is allowed and no explicit skip is required.
pub fn assert_in_subgroup(p: Point) {
    assert_on_curve(p);
    let cofactor_cleared = scalar_mul(SUBGROUP_ORDER, p);
    assert(is_neutral(cofactor_cleared), "bjj: DH base not in prime-order subgroup");
}

/// `true` iff `p` is the neutral element `(0, 1)`.
pub fn is_neutral(p: Point) -> bool {
    (p.x == 0) & (p.y == 1)
}
