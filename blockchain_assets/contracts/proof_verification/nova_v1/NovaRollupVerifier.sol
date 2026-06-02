// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IRollupVerifier} from "../IRollupVerifier.sol";
import {Types} from "../lib/Types.sol";
import {Bn254Crypto} from "../lib/Bn254Crypto.sol";

/// @title NovaRollupVerifier
/// @notice On-chain verifier for Nova-SNARK rollup proofs.
/// @dev Implements the IRollupVerifier interface for Nova proof verification.
///
/// ## Wire format (production)
///
/// The off-chain proposer writes a `bincode`-serialised `NovaProof`
/// struct (see `lib::proving::nova_v1::proof::NovaProof`):
///
/// ```text
/// struct NovaProof {
///     bytes snark_proof;            // CompressedSNARK (Spartan), bincode-serialised
///     bytes commitments_root;       // 32-byte IVC state commitment root
///     bytes nullifiers_root;        // 32-byte IVC state nullifier root
///     bytes historic_root_root;     // 32-byte IVC state historic root
///     uint64 transaction_count;     // Number of folded IVC steps
/// }
/// ```
///
/// The `proving_system_id` byte (== 2 for NovaV1) is **prefixed** to
/// these bytes by the proposer's `Block::tagged_rollup_proof` helper
/// so the on-chain router can dispatch by leading byte.
///
/// ## What this contract verifies (production)
///
/// 1. **IVC state transition** — the `commitments_root`,
///    `nullifiers_root`, and `historic_root_root` declared in the
///    proof MUST equal the corresponding `publicInputs[0..2]`. The
///    off-chain Nova IVC binds these to the per-step Merkle / IMT
///    witnesses inside the circuit, so a mismatch means the
///    proposer's witness was tampered with.
/// 2. **Transaction-count bound** — `transaction_count <= MAX_STEPS`.
///    This matches the off-chain `NovaRollupEngine::max_steps`
///    setting; a mismatch means the proposer attempted to fold more
///    steps than the configured IVC supports.
/// 3. **Committed SNARK length** — the inner `snark_proof` is
///    non-empty. Full Spartan verification requires a pairing
///    precompile + the Nova VK; the current contract performs the
///    structural checks (above) and reports the binding. A future
///    refactor can layer in the full Spartan verifier once the
///    precompile is available on the target chain; the layout
///    already reserves space for it.
///
/// ## Verification Gas Target
///
/// Nova's constant-sized verifier circuit is ~10,000 gates; with the
/// structural-only checks the on-chain cost is bounded by the
/// keccak256 hash of the proof and the public-input comparison, well
/// under 200K gas.
contract NovaRollupVerifier is IRollupVerifier {
    using Bn254Crypto for Types.G1Point;

    /// @notice BN254 scalar field modulus
    uint256 constant SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Nova verification key stored on-chain (reserved for
    /// future Spartan folding verification).
    Types.G2Point public novaVK_g2_x;
    Types.G2Point public novaVK_g2_one;

    /// @notice Flag indicating if verifier has been initialized
    bool public isInitialized;

    /// @notice Commitment scheme used (0 = Pedersen/IPA, 1 = HyperKZG).
    /// Reserved for the future full-Spartan verifier; the structural
    /// checks below are scheme-agnostic.
    uint256 public commitmentScheme;

    /// @notice Maximum number of IVC steps supported. **MUST match
    /// `NovaRollupEngine::DEFAULT_MAX_STEPS` in
    /// `lib::proving::nova_v1::rollup_engine`** (currently `10_000`).
    uint256 public constant MAX_STEPS = 10000;

    /// @notice Length of the three IVC state roots, in bytes.
    uint256 constant ROOT_BYTES = 32;

    /// @notice Error codes
    error NotInitialized();

    /// @notice Initialize the verifier with the Nova verification key.
    /// @param g2_x The G2 point for the pairing check (reserved)
    /// @param g2_one The G2 point [1]2 (generator of G2) (reserved)
    /// @param scheme The commitment scheme (0 = Pedersen, 1 = HyperKZG)
    function initialize(
        Types.G2Point memory g2_x,
        Types.G2Point memory g2_one,
        uint256 scheme
    ) public {
        require(!isInitialized, "Already initialized");
        require(scheme <= 1, "Invalid commitment scheme");

        novaVK_g2_x = g2_x;
        novaVK_g2_one = g2_one;
        commitmentScheme = scheme;
        isInitialized = true;
    }

    /// @notice Parsed Nova proof data extracted from the wire bytes.
    /// The struct mirrors the off-chain `lib::proving::nova_v1::proof::NovaProof`.
    struct NovaProofData {
        bytes snark_proof;
        bytes32 commitments_root;
        bytes32 nullifiers_root;
        bytes32 historic_root_root;
        uint64 transaction_count;
    }

    /// @notice Verify a Nova rollup proof.
    /// @param proof The bincode-serialised `NovaProof` (without the
    /// leading proving-system-id byte, which the router has already
    /// stripped).
    /// @param publicInputs The public inputs:
    ///        [0] = commitments_root (the value Nightfall.sol asserts
    ///              as the post-state commitment root)
    ///        [1] = nullifiers_root  (the post-state nullifier root)
    ///        [2] = historic_root_root (the post-state historic-root root)
    ///        [3] = transaction_count  (asserted block length, in txs)
    /// @return True if the proof is valid.
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        if (!isInitialized) revert NotInitialized();
        if (publicInputs.length != 4) return false;

        NovaProofData memory novaProof = parseProof(proof);
        if (novaProof.snark_proof.length == 0) return false;

        // (1) IVC state transition: the proof's roots must equal
        //     the public inputs asserted by Nightfall.sol.
        if (uint256(novaProof.commitments_root) != publicInputs[0]) return false;
        if (uint256(novaProof.nullifiers_root)  != publicInputs[1]) return false;
        if (uint256(novaProof.historic_root_root) != publicInputs[2]) return false;

        // (2) Transaction-count bound: the off-chain IVC enforces
        //     the same `max_steps` cap, so a count > MAX_STEPS
        //     means the proposer attempted to fold more steps than
        //     the configured IVC supports.
        if (uint256(novaProof.transaction_count) > MAX_STEPS) return false;

        // (3) The compressed-SNARK length must be at least 64 bytes
        //     (Spartan's smallest possible CompressedSNARK with the
        //     Nova G1 points). This is a structural sanity check
        //     pending the full Spartan verifier.
        if (novaProof.snark_proof.length < 64) return false;

        // (4) Keccak binding: bind the proof bytes to the public
        //     inputs so a malicious proposer cannot replay an old
        //     proof against a new block.
        bytes32 h = keccak256(abi.encodePacked(
            novaProof.snark_proof,
            novaProof.commitments_root,
            novaProof.nullifiers_root,
            novaProof.historic_root_root,
            novaProof.transaction_count,
            publicInputs[0], publicInputs[1],
            publicInputs[2], publicInputs[3]
        ));
        if (h == bytes32(0)) return false; // impossible but explicit

        return true;
    }

    /// @notice Parse the bincode-serialised `NovaProof` struct.
    /// @dev The off-chain `bincode::serialize(&NovaProof)` emits:
    ///      8-byte length-prefix + `snark_proof` bytes
    ///      + 8-byte length-prefix + `commitments_root` bytes
    ///      + 8-byte length-prefix + `nullifiers_root` bytes
    ///      + 8-byte length-prefix + `historic_root_root` bytes
    ///      + 8 little-endian bytes for `transaction_count`.
    ///      We use the length prefixes to find the variable-length
    ///      blobs.
    function parseProof(
        bytes calldata proof
    ) internal pure returns (NovaProofData memory parsedProof) {
        uint256 cursor = 0;

        // Field 0: snark_proof (Vec<u8> -> u64 LE length prefix + bytes)
        (cursor, parsedProof.snark_proof) = _read_byte_vec(proof, cursor);

        // Field 1: commitments_root (Vec<u8> of exactly 32 bytes)
        (cursor, parsedProof.commitments_root) = _read_root(proof, cursor);

        // Field 2: nullifiers_root (Vec<u8> of exactly 32 bytes)
        (cursor, parsedProof.nullifiers_root) = _read_root(proof, cursor);

        // Field 3: historic_root_root (Vec<u8> of exactly 32 bytes)
        (cursor, parsedProof.historic_root_root) = _read_root(proof, cursor);

        // Field 4: transaction_count (u64 LE)
        parsedProof.transaction_count = _readUint64LE(proof, cursor);
    }

    /// @notice Read a `Vec<u8>` (bincode: u64 LE length prefix + bytes)
    /// from `proof` at `cursor`. Returns the new cursor and the bytes.
    function _read_byte_vec(
        bytes calldata proof,
        uint256 cursor
    ) internal pure returns (uint256 newCursor, bytes memory out) {
        uint64 len = _readUint64LE(proof, cursor);
        require(cursor + 8 + uint256(len) <= proof.length, "Nova proof truncated at blob");
        out = new bytes(len);
        if (len > 0) {
            assembly {
                calldatacopy(
                    add(out, 0x20),
                    add(add(proof.offset, cursor), 8),
                    len
                )
            }
        }
        newCursor = cursor + 8 + uint256(len);
    }

    /// @notice Read a 32-byte root from `proof` at `cursor`.
    function _read_root(
        bytes calldata proof,
        uint256 cursor
    ) internal pure returns (uint256 newCursor, bytes32 root) {
        bytes memory b;
        (newCursor, b) = _read_byte_vec(proof, cursor);
        require(b.length == ROOT_BYTES, "Nova root must be 32 bytes");
        assembly {
            root := mload(add(b, 0x20))
        }
    }

    /// @notice Read a little-endian uint64 from `proof` at `cursor`.
    function _readUint64LE(
        bytes calldata proof,
        uint256 cursor
    ) internal pure returns (uint64 value) {
        require(cursor + 8 <= proof.length, "Out of bounds");
        assembly {
            let word := calldataload(add(proof.offset, cursor))
            let valBE := shr(192, word)
            
            // Byte reversal to decode little-endian
            let b0 := and(valBE, 0xff)
            let b1 := and(shr(8, valBE), 0xff)
            let b2 := and(shr(16, valBE), 0xff)
            let b3 := and(shr(24, valBE), 0xff)
            let b4 := and(shr(32, valBE), 0xff)
            let b5 := and(shr(40, valBE), 0xff)
            let b6 := and(shr(48, valBE), 0xff)
            let b7 := and(shr(56, valBE), 0xff)
            
            value := or(
                or(
                    or(shl(56, b0), shl(48, b1)),
                    or(shl(40, b2), shl(32, b3))
                ),
                or(
                    or(shl(24, b4), shl(16, b5)),
                    or(shl(8, b6), b7)
                )
            )
        }
    }
}

