// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {ECDSA384} from "../src/ECDSA384.sol";
import {Sha2Ext} from "../src/Sha2Ext.sol";

contract ECDSA384Test is Test {
    bytes public constant CURVE_A =
        hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc";
    bytes public constant CURVE_B =
        hex"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef";
    bytes public constant CURVE_GX =
        hex"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7";
    bytes public constant CURVE_GY =
        hex"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";
    bytes public constant CURVE_P =
        hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
    bytes public constant CURVE_N =
        hex"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
    bytes public constant CURVE_LOW_S_MAX =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9";

    function testEmptySig(bytes memory message) public view {
        ECDSA384.Parameters memory CURVE_PARAMETERS = ECDSA384.Parameters({
            a: CURVE_A,
            b: CURVE_B,
            gx: CURVE_GX,
            gy: CURVE_GY,
            p: CURVE_P,
            n: CURVE_N,
            lowSmax: CURVE_LOW_S_MAX
        });
        bytes memory pubKey = abi.encodePacked(
            hex"56931fd7d42942eec92298d7291371cdbac29c60230c9f635d010939ab7f8f5d977ccfe90bd7528cafa53afad6225bf61e2af4d20831aed1e6b578ccb00e1534182f6d1ee6bf524fbd62bd056d0d538c24eb7f2a436e336e139f00a072b0ba1a"
        );
        bytes memory hash = Sha2Ext.sha384(message, 0, message.length);
        bytes memory sig = abi.encodePacked(
            hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );

        require(!ECDSA384.verify(CURVE_PARAMETERS, hash, sig, pubKey));
    }
}
