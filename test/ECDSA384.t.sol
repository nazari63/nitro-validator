// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {ECDSA384} from "../src/ECDSA384.sol";
import {Sha2Ext} from "../src/Sha2Ext.sol";

contract ECDSA384Test is Test {
    function testEmptySig(bytes memory message) public view {
        ECDSA384.Parameters memory CURVE_PARAMETERS = ECDSA384.Parameters({
            a: ECDSA384.CURVE_A,
            b: ECDSA384.CURVE_B,
            gx: ECDSA384.CURVE_GX,
            gy: ECDSA384.CURVE_GY,
            p: ECDSA384.CURVE_P,
            n: ECDSA384.CURVE_N
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
