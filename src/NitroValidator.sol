// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {CertManager} from "./CertManager.sol";
import {Sha2Ext} from "./Sha2Ext.sol";
import {Asn1Decode} from "./Asn1Decode.sol";
import {ECDSA384} from "./ECDSA384.sol";
import {LibBytes} from "./LibBytes.sol";
import {NodePtr, LibNodePtr} from "./NodePtr.sol";

// adapted from https://github.com/marlinprotocol/NitroProver/blob/f1d368d1f172ad3a55cd2aaaa98ad6a6e7dcde9d/src/NitroProver.sol

contract NitroValidator {
    using LibBytes for bytes;
    using LibNodePtr for NodePtr;

    bytes32 public constant ATTESTATION_TBS_PREFIX = keccak256(hex"846a5369676e61747572653144a101382240");
    bytes32 public constant ATTESTATION_DIGEST = keccak256("SHA384");

    bytes32 public constant CERTIFICATE_KEY = keccak256(bytes("certificate"));
    bytes32 public constant PUBLIC_KEY_KEY = keccak256(bytes("public_key"));
    bytes32 public constant MODULE_ID_KEY = keccak256(bytes("module_id"));
    bytes32 public constant TIMESTAMP_KEY = keccak256(bytes("timestamp"));
    bytes32 public constant USER_DATA_KEY = keccak256(bytes("user_data"));
    bytes32 public constant CABUNDLE_KEY = keccak256(bytes("cabundle"));
    bytes32 public constant DIGEST_KEY = keccak256(bytes("digest"));
    bytes32 public constant NONCE_KEY = keccak256(bytes("nonce"));
    bytes32 public constant PCRS_KEY = keccak256(bytes("pcrs"));

    // ECDSA384 curve parameters (NIST P-384)
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

    struct Ptrs {
        NodePtr moduleID;
        uint64 timestamp;
        NodePtr digest;
        NodePtr[] pcrs;
        NodePtr cert;
        NodePtr[] cabundle;
        NodePtr publicKey;
        NodePtr userData;
        NodePtr nonce;
    }

    CertManager public immutable certManager;

    constructor(CertManager _certManager) {
        certManager = _certManager;
    }

    function validateAttestation(bytes memory attestationTbs, bytes memory signature) public returns (Ptrs memory) {
        Ptrs memory ptrs = _parseAttestation(attestationTbs);

        require(ptrs.moduleID.length() > 0, "no module id");
        require(ptrs.timestamp > 0, "no timestamp");
        require(ptrs.cabundle.length > 0, "no cabundle");
        require(
            attestationTbs.keccak(ptrs.digest.content(), ptrs.digest.length()) == ATTESTATION_DIGEST, "invalid digest"
        );
        require(1 <= ptrs.pcrs.length && ptrs.pcrs.length <= 32, "invalid pcrs");
        require(
            attestationTbs[ptrs.publicKey.header()] == Asn1Decode.NULL_VALUE
                || (1 <= ptrs.publicKey.length() && ptrs.publicKey.length() <= 1024),
            "invalid pub key"
        );
        require(
            attestationTbs[ptrs.userData.header()] == Asn1Decode.NULL_VALUE || (ptrs.userData.length() <= 512),
            "invalid user data"
        );
        require(
            attestationTbs[ptrs.nonce.header()] == Asn1Decode.NULL_VALUE || (ptrs.nonce.length() <= 512),
            "invalid nonce"
        );

        bytes memory cert = attestationTbs.slice(ptrs.cert.content(), ptrs.cert.content() + ptrs.cert.length());
        bytes[] memory cabundle = new bytes[](ptrs.cabundle.length);
        for (uint256 i = 0; i < ptrs.cabundle.length; i++) {
            cabundle[i] =
                attestationTbs.slice(ptrs.cabundle[i].content(), ptrs.cabundle[i].content() + ptrs.cabundle[i].length());
        }

        CertManager.CachedCert memory parent = certManager.verifyCertBundle(cert, cabundle);
        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        _verifySignature(parent.pubKey, hash, signature);

        return ptrs;
    }

    function _parseAttestation(bytes memory attestationTbs) internal pure returns (Ptrs memory) {
        require(attestationTbs.keccak(0, 18) == ATTESTATION_TBS_PREFIX, "invalid attestation prefix");

        NodePtr payload = _readNextElement(attestationTbs, 18);
        require(payload.header() == 0x40, "invalid attestation payload type");
        NodePtr payloadMap = _readNextElement(attestationTbs, payload.content());
        require(payloadMap.header() == 0xa0, "invalid attestation payload map type");

        Ptrs memory ptrs;
        uint256 offset = payloadMap.content();
        uint256 end = payload.content() + payload.length();
        while (offset < end) {
            NodePtr key = _readNextElement(attestationTbs, offset);
            require(key.header() == 0x60, "invalid attestation key type");
            bytes32 keyHash = attestationTbs.keccak(key.content(), key.length());
            NodePtr value = _readNextElement(attestationTbs, key.content() + key.length());
            if (keyHash == MODULE_ID_KEY) {
                require(value.header() == 0x60, "invalid module_id type");
                ptrs.moduleID = value;
                offset = value.content() + value.length();
            } else if (keyHash == DIGEST_KEY) {
                require(value.header() == 0x60, "invalid digest type");
                ptrs.digest = value;
                offset = value.content() + value.length();
            } else if (keyHash == CERTIFICATE_KEY) {
                require(value.header() == 0x40, "invalid cert type");
                ptrs.cert = value;
                offset = value.content() + value.length();
            } else if (keyHash == PUBLIC_KEY_KEY) {
                ptrs.publicKey = value;
                offset = value.content() + value.length();
            } else if (keyHash == USER_DATA_KEY) {
                ptrs.userData = value;
                offset = value.content() + value.length();
            } else if (keyHash == NONCE_KEY) {
                ptrs.nonce = value;
                offset = value.content() + value.length();
            } else if (keyHash == TIMESTAMP_KEY) {
                require(value.header() == 0x00, "invalid timestamp type");
                ptrs.timestamp = uint64(value.length());
                offset = value.content();
            } else if (keyHash == CABUNDLE_KEY) {
                require(value.header() == 0x80, "invalid cabundle type");
                offset = value.content();
                ptrs.cabundle = new NodePtr[](value.length());
                for (uint256 i = 0; i < value.length(); i++) {
                    NodePtr cert = _readNextElement(attestationTbs, offset);
                    require(cert.header() == 0x40, "invalid cert type");
                    ptrs.cabundle[i] = cert;
                    offset = cert.content() + cert.length();
                }
            } else if (keyHash == PCRS_KEY) {
                require(value.header() == 0xa0, "invalid pcrs type");
                offset = value.content();
                ptrs.pcrs = new NodePtr[](value.length());
                for (uint256 i = 0; i < value.length(); i++) {
                    key = _readNextElement(attestationTbs, offset);
                    require(key.header() == 0x00, "invalid pcr key type");
                    require(key.length() < value.length(), "invalid pcr key value");
                    require(NodePtr.unwrap(ptrs.pcrs[key.length()]) == 0, "duplicate pcr key");
                    NodePtr pcr = _readNextElement(attestationTbs, key.content());
                    require(pcr.header() == 0x40, "invalid pcr type");
                    ptrs.pcrs[key.length()] = pcr;
                    offset = pcr.content() + pcr.length();
                }
            } else {
                revert("invalid attestation key");
            }
        }

        return ptrs;
    }

    function _readNextElement(bytes memory cbor, uint256 ix) internal pure returns (NodePtr) {
        uint256 _type = uint256(uint8(cbor[ix] & 0xe0));
        uint256 length = uint256(uint8(cbor[ix] & 0x1f));
        uint256 header = 1;
        if (length == 24) {
            length = uint8(cbor[ix + 1]);
            header = 2;
        } else if (length == 25) {
            length = cbor.readUint16(ix + 1);
            header = 3;
        } else if (length == 26) {
            length = cbor.readUint32(ix + 1);
            header = 5;
        } else if (length == 27) {
            length = cbor.readUint64(ix + 1);
            header = 9;
        }
        return LibNodePtr.toNodePtr(_type, ix + header, length);
    }

    function _verifySignature(bytes memory pubKey, bytes memory hash, bytes memory sig) internal view {
        ECDSA384.Parameters memory CURVE_PARAMETERS = ECDSA384.Parameters({
            a: CURVE_A,
            b: CURVE_B,
            gx: CURVE_GX,
            gy: CURVE_GY,
            p: CURVE_P,
            n: CURVE_N,
            lowSmax: CURVE_LOW_S_MAX
        });
        require(ECDSA384.verify(CURVE_PARAMETERS, hash, sig, pubKey), "invalid sig");
    }
}
