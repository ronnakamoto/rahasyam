// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title Bls12381
/// @notice BLS12-381 helpers over the EIP-2537 precompiles (`0x0b`..`0x11`),
/// plus an RFC 9380 `hash_to_curve` to G2 (ciphersuite `..._XMD:SHA-256_SSWU_RO_...`).
/// Used by {NovaCommitteeVerifier} for aggregate BLS signature verification.
/// Requires the Prague hardfork. NOT yet audited.
library Bls12381 {
    // EIP-2537 precompile addresses.
    uint256 internal constant G1ADD = 0x0b;
    uint256 internal constant G2ADD = 0x0d;
    uint256 internal constant PAIRING = 0x0f;
    uint256 internal constant MAP_FP2_TO_G2 = 0x11;
    uint256 internal constant MODEXP = 0x05;

    // Base field modulus p, encoded as a 64-byte EIP-2537 field element
    // (top 16 bytes zero).
    bytes internal constant P =
        hex"000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    function _call(uint256 addr, bytes memory input, uint256 outLen)
        internal
        view
        returns (bytes memory out)
    {
        out = new bytes(outLen);
        bool ok;
        assembly {
            ok := staticcall(gas(), addr, add(input, 0x20), mload(input), add(out, 0x20), outLen)
        }
        require(ok, "bls precompile failed");
    }

    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        require(a.length == 128 && b.length == 128, "g1Add len");
        return _call(G1ADD, abi.encodePacked(a, b), 128);
    }

    function g2Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        require(a.length == 256 && b.length == 256, "g2Add len");
        return _call(G2ADD, abi.encodePacked(a, b), 256);
    }

    function mapFp2ToG2(bytes memory fp2) internal view returns (bytes memory) {
        require(fp2.length == 128, "map len");
        return _call(MAP_FP2_TO_G2, fp2, 256);
    }

    /// @notice EIP-2537 pairing check: returns true iff the product of pairings
    /// over the (G1,G2) pairs equals 1. `pairs` is k*(128+256) bytes.
    function pairing(bytes memory pairs) internal view returns (bool) {
        require(pairs.length % 384 == 0 && pairs.length > 0, "pairing len");
        bytes memory out = _call(PAIRING, pairs, 32);
        return out[31] == 0x01;
    }

    /// @notice Reduce a 64-byte big-endian integer mod p via the modexp
    /// precompile (base^1 mod p). Returns a canonical 64-byte field element.
    function _reduceFp(bytes memory v64) internal view returns (bytes memory) {
        bytes memory input = abi.encodePacked(
            uint256(64), uint256(1), uint256(64), v64, uint8(1), P
        );
        return _call(MODEXP, input, 64);
    }

    function _slice64(bytes memory data, uint256 off) internal pure returns (bytes memory) {
        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            out[i] = data[off + i];
        }
        return out;
    }

    /// @notice RFC 9380 expand_message_xmd with SHA-256.
    function expandMessageXmd(bytes memory message, bytes memory dst, uint256 lenInBytes)
        internal
        pure
        returns (bytes memory)
    {
        require(dst.length <= 255, "dst too long");
        uint256 ell = (lenInBytes + 31) / 32; // b_in_bytes = 32
        require(ell <= 255, "ell too large");

        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        bytes memory zPad = new bytes(64); // s_in_bytes = 64 (SHA-256 block)
        bytes2 lib = bytes2(uint16(lenInBytes));

        bytes32 b0 = sha256(abi.encodePacked(zPad, message, lib, uint8(0), dstPrime));
        bytes32 b1 = sha256(abi.encodePacked(b0, uint8(1), dstPrime));

        bytes memory uniform = new bytes(lenInBytes);
        _writeWord(uniform, 0, b1);

        bytes32 prev = b1;
        for (uint256 i = 2; i <= ell; i++) {
            bytes32 bi = sha256(abi.encodePacked(b0 ^ prev, uint8(i), dstPrime));
            _writeWord(uniform, (i - 1) * 32, bi);
            prev = bi;
        }
        return uniform;
    }

    function _writeWord(bytes memory dst, uint256 off, bytes32 word) internal pure {
        assembly {
            mstore(add(add(dst, 0x20), off), word)
        }
    }

    /// @notice RFC 9380 hash_to_field for Fp2, count=2. Returns two 128-byte
    /// Fp2 elements (each c0||c1).
    function hashToFieldFp2(bytes memory message, bytes memory dst)
        internal
        view
        returns (bytes memory u0, bytes memory u1)
    {
        bytes memory uniform = expandMessageXmd(message, dst, 256);
        bytes memory c0_0 = _reduceFp(_slice64(uniform, 0));
        bytes memory c1_0 = _reduceFp(_slice64(uniform, 64));
        bytes memory c0_1 = _reduceFp(_slice64(uniform, 128));
        bytes memory c1_1 = _reduceFp(_slice64(uniform, 192));
        u0 = abi.encodePacked(c0_0, c1_0);
        u1 = abi.encodePacked(c0_1, c1_1);
    }

    /// @notice RFC 9380 hash_to_curve to G2: map each field element and add.
    /// The EIP-2537 map precompile clears the cofactor, and cofactor clearing
    /// is linear, so map(u0)+map(u1) == clear_cofactor(mc(u0)+mc(u1)).
    function hashToG2(bytes memory message, bytes memory dst)
        internal
        view
        returns (bytes memory)
    {
        (bytes memory u0, bytes memory u1) = hashToFieldFp2(message, dst);
        bytes memory q0 = mapFp2ToG2(u0);
        bytes memory q1 = mapFp2ToG2(u1);
        return g2Add(q0, q1);
    }
}
