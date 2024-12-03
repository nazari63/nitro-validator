// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {Sha2Ext} from "./Sha2Ext.sol";
import {Asn1Decode, Asn1Ptr, LibAsn1Ptr} from "./Asn1Decode.sol";
import {ECDSA384} from "./ECDSA384.sol";
import {LibBytes} from "./LibBytes.sol";

interface ICertManager {
    struct CachedCert {
        uint256 notAfter;
        int256 maxPathLen;
        bytes pubKey;
    }

    function verifyCert(bytes memory cert, bool clientCert, bytes32 parentCertHash)
        external
        returns (CachedCert memory);

    function verifyCertBundle(bytes memory certificate, bytes[] calldata cabundle)
        external
        returns (CachedCert memory);
}
