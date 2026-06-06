// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title NovaProofParsing
/// @notice Shared parser + canonical attestation preimage for Nova rollup
/// proofs. Extracted verbatim (logic-identical) from `NovaRollupVerifier`'s
/// internal helpers so the ECDSA gate and the BLS committee gate decode the
/// on-wire `NovaProof` and bind public inputs the exact same way.
///
/// The off-chain single source of truth is
/// `lib::proving::nova_v1::attestation::attestation_preimage`.
library NovaProofParsing {
    /// @notice Domain separator for the attestation preimage. MUST match
    /// `ATTEST_DOMAIN` in `attestation.rs` and `NovaRollupVerifier`.
    string internal constant ATTEST_DOMAIN = "NF4_NOVA_ATTEST_V1";

    uint256 internal constant ROOT_BYTES = 32;

    struct NovaProofData {
        bytes snark_proof;
        bytes32 commitments_root;
        bytes32 nullifiers_root;
        bytes32 historic_root_root;
        uint64 transaction_count;
    }

    /// @notice Parse the bincode-serialised `NovaProof` struct: four
    /// length-prefixed byte vectors followed by a u64 LE `transaction_count`.
    /// `cursor` is the offset immediately after `transaction_count` (where any
    /// appended signature region begins). `ok` is false on malformed input.
    function parseProof(bytes calldata proof)
        internal
        pure
        returns (NovaProofData memory parsedProof, uint256 cursor, bool ok)
    {
        (cursor, parsedProof.snark_proof, ok) = _readByteVec(proof, 0);
        if (!ok) return (parsedProof, cursor, false);

        (cursor, parsedProof.commitments_root, ok) = _readRoot(proof, cursor);
        if (!ok) return (parsedProof, cursor, false);

        (cursor, parsedProof.nullifiers_root, ok) = _readRoot(proof, cursor);
        if (!ok) return (parsedProof, cursor, false);

        (cursor, parsedProof.historic_root_root, ok) = _readRoot(proof, cursor);
        if (!ok) return (parsedProof, cursor, false);

        if (cursor + 8 > proof.length) return (parsedProof, cursor, false);
        parsedProof.transaction_count = _readUint64LE(proof, cursor);
        cursor += 8;
        ok = true;
    }

    function _readByteVec(bytes calldata proof, uint256 cursor)
        internal
        pure
        returns (uint256 newCursor, bytes memory out, bool ok)
    {
        if (cursor + 8 > proof.length) return (cursor, out, false);
        uint64 len = _readUint64LE(proof, cursor);
        if (cursor + 8 + uint256(len) > proof.length) return (cursor, out, false);
        out = new bytes(len);
        if (len > 0) {
            assembly {
                calldatacopy(add(out, 0x20), add(add(proof.offset, cursor), 8), len)
            }
        }
        newCursor = cursor + 8 + uint256(len);
        ok = true;
    }

    function _readRoot(bytes calldata proof, uint256 cursor)
        internal
        pure
        returns (uint256 newCursor, bytes32 root, bool ok)
    {
        bytes memory b;
        (newCursor, b, ok) = _readByteVec(proof, cursor);
        if (!ok) return (newCursor, root, false);
        if (b.length != ROOT_BYTES) return (newCursor, root, false);
        assembly {
            root := mload(add(b, 0x20))
        }
        ok = true;
    }

    function _readUint64LE(bytes calldata proof, uint256 cursor)
        internal
        pure
        returns (uint64 value)
    {
        assembly {
            let word := calldataload(add(proof.offset, cursor))
            let valBE := shr(192, word)
            let b0 := and(valBE, 0xff)
            let b1 := and(shr(8, valBE), 0xff)
            let b2 := and(shr(16, valBE), 0xff)
            let b3 := and(shr(24, valBE), 0xff)
            let b4 := and(shr(32, valBE), 0xff)
            let b5 := and(shr(40, valBE), 0xff)
            let b6 := and(shr(48, valBE), 0xff)
            let b7 := and(shr(56, valBE), 0xff)
            value :=
                or(
                    or(or(shl(56, b0), shl(48, b1)), or(shl(40, b2), shl(32, b3))),
                    or(or(shl(24, b4), shl(16, b5)), or(shl(8, b6), b7))
                )
        }
    }

    /// @notice Canonical attestation preimage hash. Binds the proof bytes, the
    /// three IVC roots, the transaction count, the four public inputs, and
    /// domain-separates by `block.chainid` and the caller verifier address.
    /// `internal` so `address(this)` resolves to the calling verifier.
    function attestPreimage(
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
}
