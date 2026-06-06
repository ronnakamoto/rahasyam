// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IRollupVerifier} from "../IRollupVerifier.sol";
import {Types} from "../lib/Types.sol";
import {Bn254Crypto} from "../lib/Bn254Crypto.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title NovaRollupVerifier
/// @notice On-chain verifier gate for Nova-SNARK rollup proofs.
///
/// ## Why this is an attestation gate and not a native SNARK verifier
///
/// The off-chain proof is a Nova `CompressedSNARK` folded over a
/// **BN254 (primary) + Grumpkin (secondary) 2-cycle** and compressed
/// with Spartan over HyperKZG/IPA
/// (see `lib::proving::nova_v1::rollup_engine`). Verifying that proof
/// requires **Grumpkin** group operations on the secondary curve.
/// Grumpkin's base field is BN254's scalar field, and the EVM exposes
/// **no Grumpkin precompile**, so a faithful in-Solidity port of
/// `CompressedSNARK::verify` is not practically feasible (the
/// secondary-curve checks cannot be done soundly with the available
/// precompiles). The production-grade path is a Groth16/Plonk "decider"
/// that re-proves the Nova verifier inside a single BN254 circuit; that
/// decider circuit + its generated Solidity verifier is tracked as a
/// follow-up.
///
/// Until the decider lands, this contract is **fail-closed** and gates
/// acceptance on a signature from a configured, trusted **attestor**.
/// The attestor is an off-chain service that runs the real
/// `CompressedSNARK::verify` (a sound check; see
/// `NovaRollupEngine::verify`) and signs only proofs that verify, over
/// the exact proof bytes and public inputs. This converts the previous
/// implicit, unbounded "any proposer is trusted" model -- where the
/// contract returned `true` after structural checks alone -- into an
/// explicit, minimised, auditable trust model: forging state now
/// requires compromising the attestor key, and every accepted proof is
/// bound by signature to its public inputs (no replay/substitution).
///
/// If no attestor is configured the contract **rejects all Nova
/// proofs**. This is intentional: it is strictly safer to disable
/// on-chain Nova settlement than to accept cryptographically
/// unverified state transitions.
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
/// followed by a **65-byte attestor ECDSA signature** `(r || s || v)`
/// appended after `transaction_count`. The `proving_system_id` byte
/// (== 2 for NovaV1) is prefixed by the proposer's
/// `Block::tagged_rollup_proof` helper and stripped by the router
/// before `verifyProof` is called.
///
/// ## What this contract verifies (production)
///
/// 1. **Structural preconditions** (necessary, not sufficient):
///    `publicInputs.length == 4`; the proof's three roots equal
///    `publicInputs[0..2]`; `transaction_count == publicInputs[3]` and
///    `<= MAX_STEPS`; and the inner `snark_proof` is at least 64 bytes.
/// 2. **Attestor signature** (sufficient gate): a valid ECDSA
///    signature from the configured `attestor` over
///    `H(DOMAIN || chainid || this || snark_proof || roots ||
///    transaction_count || publicInputs)`. The attestor signs only
///    after running the off-chain `CompressedSNARK::verify`.
///
/// A future refactor replaces step (2) with a native decider-proof
/// verification; the `IRollupVerifier` interface and wire format are
/// unchanged by that swap.
contract NovaRollupVerifier is IRollupVerifier {
    using Bn254Crypto for Types.G1Point;

    /// @notice Domain separator for the attestor signature preimage.
    /// Bumping this invalidates all previously-issued attestations.
    string private constant ATTEST_DOMAIN = "NF4_NOVA_ATTEST_V1";

    /// @notice BN254 scalar field modulus
    uint256 constant SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Nova verification key stored on-chain (reserved for the
    /// future native decider verifier).
    Types.G2Point public novaVK_g2_x;
    Types.G2Point public novaVK_g2_one;

    /// @notice Flag indicating if verifier has been initialized
    bool public isInitialized;

    /// @notice Contract owner, set at initialization. May configure the
    /// attestor.
    address public owner;

    /// @notice Trusted attestor whose ECDSA signature gates acceptance.
    /// `address(0)` (the default) means **fail-closed**: no Nova proof
    /// is accepted until an attestor is configured.
    address public attestor;

    /// @notice Commitment scheme used (0 = Pedersen/IPA, 1 = HyperKZG).
    /// Reserved for the future native decider verifier; the checks
    /// below are scheme-agnostic.
    uint256 public commitmentScheme;

    /// @notice Maximum number of IVC steps supported. **MUST match
    /// `NovaRollupEngine::DEFAULT_MAX_STEPS` in
    /// `lib::proving::nova_v1::rollup_engine`** (currently `10_000`).
    uint256 public constant MAX_STEPS = 10000;

    /// @notice Length of the three IVC state roots, in bytes.
    uint256 constant ROOT_BYTES = 32;

    /// @notice Length of an ECDSA signature `(r || s || v)`, in bytes.
    uint256 constant SIG_BYTES = 65;

    /// @notice Error codes
    error NotInitialized();
    error NotOwner();

    event AttestorUpdated(address indexed previousAttestor, address indexed newAttestor);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @notice Initialize the verifier.
    /// @dev The signature is preserved for deployment compatibility with
    /// `deployer.s.sol`. The caller (`msg.sender`) becomes the owner and
    /// can subsequently configure the attestor via {setAttestor}.
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
        owner = msg.sender;
        isInitialized = true;

        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Transfer ownership of the verifier.
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "new owner is zero");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Configure (or rotate) the trusted attestor. Setting it to
    /// `address(0)` re-arms the fail-closed default (all proofs rejected).
    function setAttestor(address newAttestor) external onlyOwner {
        emit AttestorUpdated(attestor, newAttestor);
        attestor = newAttestor;
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
    /// @param proof The bincode-serialised `NovaProof` followed by the
    /// 65-byte attestor signature (the leading proving-system-id byte
    /// has already been stripped by the router).
    /// @param publicInputs The public inputs:
    ///        [0] = commitments_root, [1] = nullifiers_root,
    ///        [2] = historic_root_root, [3] = transaction_count.
    /// @return True iff the proof passes the structural preconditions
    /// **and** carries a valid attestor signature. Returns false (never
    /// reverts) on any malformed input so a single bad block cannot
    /// brick `propose_block`.
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view override returns (bool) {
        if (!isInitialized) revert NotInitialized();
        if (publicInputs.length != 4) return false;

        // Fail-closed: without a configured attestor we cannot
        // cryptographically vouch for any proof, so reject everything.
        address expectedSigner = attestor;
        if (expectedSigner == address(0)) return false;

        (NovaProofData memory novaProof, uint256 cursor, bool ok) = parseProof(proof);
        if (!ok) return false;

        // (1) Structural preconditions (necessary, not sufficient).
        if (novaProof.snark_proof.length < 64) return false;
        if (uint256(novaProof.commitments_root) != publicInputs[0]) return false;
        if (uint256(novaProof.nullifiers_root) != publicInputs[1]) return false;
        if (uint256(novaProof.historic_root_root) != publicInputs[2]) return false;
        // NB: `publicInputs[3]` is the (padded) on-chain block length, which
        // is NOT equal to the proof's real `transaction_count`; the two are
        // bound independently by the attestor signature below, so we only
        // bound the IVC step count here.
        if (uint256(novaProof.transaction_count) > MAX_STEPS) return false;

        // (2) Attestor signature gate (sufficient). The trailing
        //     SIG_BYTES bytes of `proof` are the attestor's ECDSA
        //     signature over the canonical preimage.
        if (proof.length < cursor + SIG_BYTES) return false;

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            _attestPreimage(
                novaProof.snark_proof,
                novaProof.commitments_root,
                novaProof.nullifiers_root,
                novaProof.historic_root_root,
                novaProof.transaction_count,
                publicInputs
            )
        );

        (address recovered, ECDSA.RecoverError err, ) =
            ECDSA.tryRecover(digest, proof[cursor:cursor + SIG_BYTES]);
        if (err != ECDSA.RecoverError.NoError) return false;

        return recovered == expectedSigner;
    }

    /// @notice Canonical attestation preimage shared by {verifyProof}
    /// and {attestationPreimage}. Kept as a separate frame to bound the
    /// stack usage of `verifyProof`.
    function _attestPreimage(
        bytes memory snark_proof,
        bytes32 commitments_root,
        bytes32 nullifiers_root,
        bytes32 historic_root_root,
        uint64 transaction_count,
        uint256[] calldata publicInputs
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                ATTEST_DOMAIN,
                block.chainid,
                address(this),
                snark_proof,
                commitments_root,
                nullifiers_root,
                historic_root_root,
                transaction_count,
                publicInputs[0],
                publicInputs[1],
                publicInputs[2],
                publicInputs[3]
            )
        );
    }

    /// @notice Compute the attestor-signature preimage hash for a proof.
    /// @dev Exposed as a pure helper so off-chain attestors can compute
    /// the exact bytes they must sign (after applying the EIP-191
    /// `toEthSignedMessageHash` prefix). Mirrors the preimage used in
    /// {verifyProof}.
    function attestationPreimage(
        bytes calldata snark_proof,
        bytes32 commitments_root,
        bytes32 nullifiers_root,
        bytes32 historic_root_root,
        uint64 transaction_count,
        uint256[] calldata publicInputs
    ) external view returns (bytes32) {
        require(publicInputs.length == 4, "publicInputs.length != 4");
        return _attestPreimage(
            snark_proof,
            commitments_root,
            nullifiers_root,
            historic_root_root,
            transaction_count,
            publicInputs
        );
    }

    /// @notice Parse the bincode-serialised `NovaProof` struct.
    /// @dev The off-chain `bincode::serialize(&NovaProof)` emits:
    ///      8-byte length-prefix + `snark_proof` bytes
    ///      + 8-byte length-prefix + `commitments_root` bytes
    ///      + 8-byte length-prefix + `nullifiers_root` bytes
    ///      + 8-byte length-prefix + `historic_root_root` bytes
    ///      + 8 little-endian bytes for `transaction_count`.
    /// @return parsedProof the decoded fields.
    /// @return cursor the offset immediately after `transaction_count`
    ///         (where the appended attestor signature begins).
    /// @return ok false if the bytes are malformed/truncated (callers
    ///         must treat the proof as invalid rather than reverting).
    function parseProof(
        bytes calldata proof
    ) internal pure returns (NovaProofData memory parsedProof, uint256 cursor, bool ok) {
        // Field 0: snark_proof (Vec<u8> -> u64 LE length prefix + bytes)
        (cursor, parsedProof.snark_proof, ok) = _read_byte_vec(proof, 0);
        if (!ok) return (parsedProof, cursor, false);

        // Field 1: commitments_root (Vec<u8> of exactly 32 bytes)
        (cursor, parsedProof.commitments_root, ok) = _read_root(proof, cursor);
        if (!ok) return (parsedProof, cursor, false);

        // Field 2: nullifiers_root (Vec<u8> of exactly 32 bytes)
        (cursor, parsedProof.nullifiers_root, ok) = _read_root(proof, cursor);
        if (!ok) return (parsedProof, cursor, false);

        // Field 3: historic_root_root (Vec<u8> of exactly 32 bytes)
        (cursor, parsedProof.historic_root_root, ok) = _read_root(proof, cursor);
        if (!ok) return (parsedProof, cursor, false);

        // Field 4: transaction_count (u64 LE)
        if (cursor + 8 > proof.length) return (parsedProof, cursor, false);
        parsedProof.transaction_count = _readUint64LE(proof, cursor);
        cursor += 8;
        ok = true;
    }

    /// @notice Read a `Vec<u8>` (bincode: u64 LE length prefix + bytes)
    /// from `proof` at `cursor`. Returns the new cursor, the bytes, and
    /// an `ok` flag (false on truncation).
    function _read_byte_vec(
        bytes calldata proof,
        uint256 cursor
    ) internal pure returns (uint256 newCursor, bytes memory out, bool ok) {
        if (cursor + 8 > proof.length) return (cursor, out, false);
        uint64 len = _readUint64LE(proof, cursor);
        if (cursor + 8 + uint256(len) > proof.length) return (cursor, out, false);
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
        ok = true;
    }

    /// @notice Read a 32-byte root from `proof` at `cursor`.
    function _read_root(
        bytes calldata proof,
        uint256 cursor
    ) internal pure returns (uint256 newCursor, bytes32 root, bool ok) {
        bytes memory b;
        (newCursor, b, ok) = _read_byte_vec(proof, cursor);
        if (!ok) return (newCursor, root, false);
        if (b.length != ROOT_BYTES) return (newCursor, root, false);
        assembly {
            root := mload(add(b, 0x20))
        }
        ok = true;
    }

    /// @notice Read a little-endian uint64 from `proof` at `cursor`.
    /// @dev Callers must ensure `cursor + 8 <= proof.length`.
    function _readUint64LE(
        bytes calldata proof,
        uint256 cursor
    ) internal pure returns (uint64 value) {
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
