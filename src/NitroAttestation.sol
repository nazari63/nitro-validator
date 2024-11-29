// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {NodePtr, LibNodePtr} from "./NodePtr.sol";
import {LibBytes} from "./LibBytes.sol";

library NitroAttestation {
    using LibNodePtr for NodePtr;
    using LibBytes for bytes;

    bytes32 public constant ATTESTATION_TBS_PREFIX = keccak256(hex"846a5369676e61747572653144a101382240");
    bytes32 public constant CERTIFICATE_KEY = keccak256(bytes("certificate"));
    bytes32 public constant PUBLIC_KEY_KEY = keccak256(bytes("public_key"));
    bytes32 public constant MODULE_ID_KEY = keccak256(bytes("module_id"));
    bytes32 public constant TIMESTAMP_KEY = keccak256(bytes("timestamp"));
    bytes32 public constant USER_DATA_KEY = keccak256(bytes("user_data"));
    bytes32 public constant CABUNDLE_KEY = keccak256(bytes("cabundle"));
    bytes32 public constant DIGEST_KEY = keccak256(bytes("digest"));
    bytes32 public constant NONCE_KEY = keccak256(bytes("nonce"));
    bytes32 public constant PCRS_KEY = keccak256(bytes("pcrs"));

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

    function parseAttestation(bytes memory attestationTbs) internal view returns (Ptrs memory) {
        require(attestationTbs.keccak(0, 18) == ATTESTATION_TBS_PREFIX, "invalid attestation prefix");

        NodePtr payload = readNextElement(attestationTbs, 18);
        require(payload.header() == 0x40, "invalid attestation payload type");
        NodePtr payloadMap = readNextElement(attestationTbs, payload.content());
        require(payloadMap.header() == 0xa0, "invalid attestation payload map type");

        Ptrs memory ptrs;
        uint256 offset = payloadMap.content();
        uint256 end = payload.content() + payload.length();
        while (offset < end) {
            NodePtr key = readNextElement(attestationTbs, offset);
            require(key.header() == 0x60, "invalid attestation key type");
            bytes32 keyHash = attestationTbs.keccak(key.content(), key.length());
            NodePtr value = readNextElement(attestationTbs, key.content() + key.length());
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
                    NodePtr cert = readNextElement(attestationTbs, offset);
                    require(cert.header() == 0x40, "invalid cert type");
                    ptrs.cabundle[i] = cert;
                    offset = cert.content() + cert.length();
                }
            } else if (keyHash == PCRS_KEY) {
                require(value.header() == 0xa0, "invalid pcrs type");
                offset = value.content();
                ptrs.pcrs = new NodePtr[](value.length());
                for (uint256 i = 0; i < value.length(); i++) {
                    key = readNextElement(attestationTbs, offset);
                    require(key.header() == 0x00, "invalid pcr key type");
                    require(key.length() == i, "invalid pcr key value");
                    NodePtr pcr = readNextElement(attestationTbs, key.content());
                    require(pcr.header() == 0x40, "invalid pcr type");
                    ptrs.pcrs[i] = pcr;
                    offset = pcr.content() + pcr.length();
                }
            } else {
                revert("invalid attestation key");
            }
        }

        return ptrs;
    }

    function readNextElement(bytes memory cbor, uint256 ix) private pure returns (NodePtr) {
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
}
