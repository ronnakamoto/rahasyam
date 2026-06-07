// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IRollupVerifier} from "../IRollupVerifier.sol";
import {Bls12381} from "../lib/Bls12381.sol";
import {NovaProofParsing} from "../lib/NovaProofParsing.sol";

/// @title NovaCommitteeVerifier
/// @notice Trustless-leaning replacement for the single-attestor ECDSA gate
/// (`NovaRollupVerifier`): a `t-of-N` committee of independent attestors, each
/// of which runs the sound off-chain `CompressedSNARK::verify`, co-signs the
/// canonical attestation preimage with BLS12-381, and whose aggregate signature
/// is verified on-chain with a single EIP-2537 pairing check.
///
/// Trust model: soundness now requires `>= t` of `N` attestors to be honest and
/// non-colluding (a strict upgrade over one key) — NOT cryptographically
/// trustless. This is the robustness bridge to the ZK decider (plan B2).
///
/// Scheme: min-pubkey BLS (PK in G1, signature in G2), ciphersuite
/// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`; proof-of-possession on
/// registration defends against rogue-key attacks.
///
/// Wire format (`IRollupVerifier.verifyProof`): the bincode `NovaProof` blob
/// (parsed by {NovaProofParsing}) followed by the aggregate signature region:
/// `sigma` (G2, 256 bytes) || `bitmap` (uint256, 32 bytes; bit i set => attestor
/// i signed). Spike-quality; not audited.
contract NovaCommitteeVerifier is IRollupVerifier {
    /// @notice Negated G1 generator (EIP-2537 encoding) for the pairing
    /// `e(-G1, sigma) * e(apk, H(m)) == 1`.
    bytes private constant NEG_G1 =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    bytes private constant SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    bytes private constant POP_DST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    /// @notice Aggregate signature (256) + signer bitmap (32) trailing region.
    uint256 private constant SIG_REGION = 288;
    /// @notice Max IVC steps; MUST match `NovaRollupVerifier.MAX_STEPS`.
    uint256 public constant MAX_STEPS = 10000;

    address public owner;
    /// @notice Registered attestor G1 pubkeys (each a 128-byte EIP-2537 point).
    bytes[] private pubkeys;
    /// @notice Acceptance threshold `t`. Zero => fail-closed (reject all).
    uint256 public threshold;

    error NotOwner();
    error BadPoP();
    error BadPubkeyLen();
    error IndexOOB();

    event AttestorAdded(uint256 indexed index);
    event AttestorRemoved(uint256 indexed index);
    event ThresholdSet(uint256 threshold);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address initialOwner) {
        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    // ----------------------------------------------------------------
    // Governance
    // ----------------------------------------------------------------

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "new owner is zero");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Register an attestor after verifying its proof-of-possession
    /// `pop = sk * H_pop(pk)` (rogue-key defence). `pk` is the 128-byte G1
    /// pubkey; the PoP message is `pk` itself under {POP_DST}.
    function addAttestor(bytes calldata pk, bytes calldata pop) external onlyOwner {
        if (pk.length != 128) revert BadPubkeyLen();
        bytes memory hpop = Bls12381.hashToG2(pk, POP_DST);
        // e(-G1, pop) * e(pk, H_pop(pk)) == 1
        bytes memory pairs = abi.encodePacked(NEG_G1, pop, pk, hpop);
        if (!Bls12381.pairing(pairs)) revert BadPoP();
        pubkeys.push(pk);
        emit AttestorAdded(pubkeys.length - 1);
    }

    /// @notice Remove an attestor (swap-and-pop; note this reindexes the last
    /// attestor into `index`, so operators must re-coordinate bitmaps).
    function removeAttestor(uint256 index) external onlyOwner {
        if (index >= pubkeys.length) revert IndexOOB();
        pubkeys[index] = pubkeys[pubkeys.length - 1];
        pubkeys.pop();
        emit AttestorRemoved(index);
    }

    function setThreshold(uint256 t) external onlyOwner {
        threshold = t;
        emit ThresholdSet(t);
    }

    function attestorCount() external view returns (uint256) {
        return pubkeys.length;
    }

    function pubkeyAt(uint256 index) external view returns (bytes memory) {
        return pubkeys[index];
    }

    // ----------------------------------------------------------------
    // Verification (IRollupVerifier)
    // ----------------------------------------------------------------

    /// @inheritdoc IRollupVerifier
    /// @dev Returns false (never reverts) on any malformed input so a single bad
    /// block cannot brick `propose_block`.
    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs)
        external
        view
        override
        returns (bool)
    {
        if (publicInputs.length != 4) return false;
        // Fail-closed: no committee or no threshold => reject everything.
        if (threshold == 0 || pubkeys.length == 0) return false;

        (NovaProofParsing.NovaProofData memory p, uint256 cursor, bool ok) =
            NovaProofParsing.parseProof(proof);
        if (!ok) return false;

        // Structural preconditions (necessary, identical to the ECDSA gate).
        if (p.snark_proof.length < 64) return false;
        if (uint256(p.commitments_root) != publicInputs[0]) return false;
        if (uint256(p.nullifiers_root) != publicInputs[1]) return false;
        if (uint256(p.historic_root_root) != publicInputs[2]) return false;
        if (uint256(p.transaction_count) > MAX_STEPS) return false;

        // Aggregate signature region: sigma (256) || bitmap (32, big-endian).
        if (proof.length < cursor + SIG_REGION) return false;
        bytes memory sigma = proof[cursor:cursor + 256];
        uint256 bitmap = uint256(_loadWord(proof, cursor + 256));

        bytes32 digest = NovaProofParsing.attestPreimage(
            p.snark_proof,
            p.commitments_root,
            p.nullifiers_root,
            p.historic_root_root,
            p.transaction_count,
            publicInputs
        );

        // Never revert: a malformed/off-curve signature must fail closed rather
        // than bubble up the precompile revert.
        try this.verifyDigest(digest, sigma, bitmap) returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
    }

    /// @notice Committee verification core: reconstruct the aggregate pubkey
    /// from the signer `bitmap`, enforce the `t-of-N` threshold, and check the
    /// BLS aggregate signature over `digest`. Public so {verifyProof} can call
    /// it under try/catch; also directly testable.
    function verifyDigest(bytes32 digest, bytes memory sigma, uint256 bitmap)
        public
        view
        returns (bool)
    {
        uint256 n = pubkeys.length;
        if (threshold == 0 || n == 0) return false;
        if (sigma.length != 256) return false;
        if (bitmap == 0) return false;
        // Reject bits set beyond the registered set.
        if (n < 256 && bitmap >> n != 0) return false;

        bytes memory apk;
        bool first = true;
        uint256 count = 0;
        for (uint256 i = 0; i < n; i++) {
            if (bitmap & (1 << i) != 0) {
                count++;
                if (first) {
                    apk = pubkeys[i];
                    first = false;
                } else {
                    apk = Bls12381.g1Add(apk, pubkeys[i]);
                }
            }
        }
        if (count < threshold) return false;

        bytes memory h = Bls12381.hashToG2(abi.encodePacked(digest), SIG_DST);
        bytes memory pairs = abi.encodePacked(NEG_G1, sigma, apk, h);
        return Bls12381.pairing(pairs);
    }

    /// @notice Canonical attestation preimage hash the committee signs. Exposed
    /// so off-chain attestors compute the exact bytes (mirrors the ECDSA gate's
    /// helper). The BLS message is this 32-byte digest, hashed to G2 under
    /// {SIG_DST}.
    function attestationPreimage(
        bytes calldata snark_proof,
        bytes32 commitments_root,
        bytes32 nullifiers_root,
        bytes32 historic_root_root,
        uint64 transaction_count,
        uint256[] calldata publicInputs
    ) external view returns (bytes32) {
        require(publicInputs.length == 4, "publicInputs.length != 4");
        return NovaProofParsing.attestPreimage(
            snark_proof,
            commitments_root,
            nullifiers_root,
            historic_root_root,
            transaction_count,
            publicInputs
        );
    }

    function _loadWord(bytes calldata data, uint256 off) private pure returns (bytes32 w) {
        assembly {
            w := calldataload(add(data.offset, off))
        }
    }
}
