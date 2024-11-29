// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {console} from "forge-std/console.sol";
import {Sha2Ext} from "./Sha2Ext.sol";
import {Asn1Decode} from "./Asn1Decode.sol";
import {NitroAttestation} from "./NitroAttestation.sol";
import {ECDSA384} from "./ECDSA384.sol";
import {LibBytes} from "./LibBytes.sol";
import {NodePtr, LibNodePtr} from "./NodePtr.sol";

contract NitroValidator {
    using Asn1Decode for bytes;
    using NitroAttestation for bytes;
    using LibBytes for bytes;
    using LibNodePtr for NodePtr;

    // @dev download the root CA cert for AWS nitro enclaves from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
    // @dev convert the base64 encoded pub key into hex to get the cert below
    bytes public constant ROOT_CA_CERT =
        hex"3082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6";
    bytes32 public constant ROOT_CA_CERT_HASH = keccak256(ROOT_CA_CERT);
    // OID 1.2.840.10045.4.3.3 represents {iso(1) member-body(2) us(840) ansi-x962(10045) signatures(4) ecdsa-with-SHA2(3) ecdsa-with-SHA384(3)}
    // which essentially means the signature algorithm is Elliptic curve Digital Signature Algorithm (DSA) coupled with the Secure Hash Algorithm 384 (SHA384) algorithm
    // @dev Sig algo is hardcoded here because the root cerificate's sig algorithm is known beforehand
    // @dev reference article for encoding https://learn.microsoft.com/en-in/windows/win32/seccertenroll/about-object-identifier
    bytes32 public constant CERT_ALGO_OID = keccak256(hex"06082a8648ce3d040303");
    // https://oid-rep.orange-labs.fr/get/1.2.840.10045.2.1
    // 1.2.840.10045.2.1 {iso(1) member-body(2) us(840) ansi-x962(10045) keyType(2) ecPublicKey(1)} represents Elliptic curve public key cryptography
    bytes32 public constant EC_PUB_KEY_OID = keccak256(hex"2a8648ce3d0201");
    // https://oid-rep.orange-labs.fr/get/1.3.132.0.34
    // 1.3.132.0.34 {iso(1) identified-organization(3) certicom(132) curve(0) ansip384r1(34)} represents NIST 384-bit elliptic curve
    bytes32 public constant SECP_384_R1_OID = keccak256(hex"2b81040022");

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

    event CertVerified(bytes32 indexed certHash, bytes32 indexed parentCertHash);

    // certHash -> expiry
    mapping(bytes32 => uint256) public certExpires;
    // certHash -> pubKey
    mapping(bytes32 => bytes) public certPubKey;

    constructor() {
        bytes memory emptyPubKey;
        _verifyCert(ROOT_CA_CERT, LibNodePtr.toNodePtr(0, 0, ROOT_CA_CERT.length), ROOT_CA_CERT_HASH, emptyPubKey);
    }

    function verifyCert(bytes memory cert, bytes32 parentCertHash) external {
        bytes memory parentPubKey = certPubKey[parentCertHash];
        require(parentPubKey.length != 0, "parent cert unverified");
        require(certExpires[parentCertHash] >= block.timestamp, "parent cert expired");
        bytes32 certHash = keccak256(cert);
        require(certPubKey[certHash].length == 0, "cert already verified");
        _verifyCert(cert, LibNodePtr.toNodePtr(0, 0, cert.length), certHash, parentPubKey);
        emit CertVerified(certHash, parentCertHash);
    }

    function verifyCertBundle(bytes memory certificate, bytes[] calldata cabundle) external returns (bytes memory) {
        bytes memory pubKey;
        for (uint256 i = 0; i < cabundle.length; i++) {
            bytes32 certHash = keccak256(cabundle[i]);
            require(i > 0 || certHash == ROOT_CA_CERT_HASH, "Root CA cert not matching");
            pubKey = _verifyCert(cabundle[i], LibNodePtr.toNodePtr(0, 0, cabundle.length), certHash, pubKey);
            require(pubKey.length != 0, "invalid pub key");
        }
        return _verifyCert(certificate, LibNodePtr.toNodePtr(0, 0, certificate.length), keccak256(certificate), pubKey);
    }

    function validateAttestation(bytes memory attestationTbs, bytes memory signature) external {
        NitroAttestation.Ptrs memory ptrs = attestationTbs.parseAttestation();

        bytes memory pubKey;
        bytes32 certHash;
        for (uint256 i = 0; i < ptrs.cabundle.length; i++) {
            certHash = attestationTbs.keccak(ptrs.cabundle[i].content(), ptrs.cabundle[i].length());
            require(i > 0 || certHash == ROOT_CA_CERT_HASH, "Root CA cert not matching");
            pubKey = _verifyCert(attestationTbs, ptrs.cabundle[i], certHash, pubKey);
            require(pubKey.length != 0, "invalid pub key");
        }
        certHash = attestationTbs.keccak(ptrs.cert.content(), ptrs.cert.length());
        pubKey = _verifyCert(attestationTbs, ptrs.cert, certHash, pubKey);

        bytes memory hash = Sha2Ext.sha384(attestationTbs, 0, attestationTbs.length);
        verifySignature(pubKey, hash, signature);
    }

    function _verifyCert(bytes memory certificate, NodePtr ptr, bytes32 certHash, bytes memory parentPubKey)
        internal
        returns (bytes memory)
    {
        // skip verification if already verified
        bytes memory pubKey = certPubKey[certHash];
        if (pubKey.length != 0) {
            require(certExpires[certHash] >= block.timestamp, "cert expired");
            return pubKey;
        }

        NodePtr root = certificate.rootOf(ptr);
        NodePtr tbsCertPtr = certificate.firstChildOf(root);
        uint256 notAfter;

        (notAfter, pubKey) = _parseTbs(certificate, tbsCertPtr);

        if (parentPubKey.length != 0 || certHash != ROOT_CA_CERT_HASH) {
            NodePtr sigAlgoPtr = certificate.nextSiblingOf(tbsCertPtr);
            require(
                certificate.keccak(sigAlgoPtr.content(), sigAlgoPtr.length()) == CERT_ALGO_OID, "invalid cert sig algo"
            );

            bytes memory hash = Sha2Ext.sha384(certificate, tbsCertPtr.header(), tbsCertPtr.totalLength());
            bytes memory sigPacked = packSig(certificate, sigAlgoPtr);
            verifySignature(parentPubKey, hash, sigPacked);
        }

        certPubKey[certHash] = pubKey;
        certExpires[certHash] = notAfter;

        return pubKey;
    }

    function packSig(bytes memory certificate, NodePtr sigAlgoPtr) internal pure returns (bytes memory) {
        NodePtr sigPtr = certificate.nextSiblingOf(sigAlgoPtr);
        NodePtr sigBPtr = certificate.bitstringAt(sigPtr);
        NodePtr sigRoot = certificate.rootOf(sigBPtr);
        NodePtr sigRPtr = certificate.firstChildOf(sigRoot);
        (uint128 rhi, uint256 rlo) = certificate.uint384At(sigRPtr);
        NodePtr sigSPtr = certificate.nextSiblingOf(sigRPtr);
        (uint128 shi, uint256 slo) = certificate.uint384At(sigSPtr);
        return abi.encodePacked(rhi, rlo, shi, slo);
    }

    function pad(bytes memory b, uint256 l) internal pure returns (bytes memory) {
        require(b.length <= l, "");
        if (b.length == l) return b;
        bytes memory padding = new bytes(l - b.length);
        return abi.encodePacked(padding, b);
    }

    function _parseTbs(bytes memory certificate, NodePtr ptr) internal view returns (uint256, bytes memory) {
        NodePtr versionPtr = certificate.firstChildOf(ptr);
        NodePtr vPtr = certificate.firstChildOf(versionPtr);
        uint256 version = certificate.uintAt(vPtr);
        // as extensions are used in cert, version should be 3 (value 2) as per https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1
        require(version == 2, "version should be 3");

        NodePtr serialPtr = certificate.nextSiblingOf(versionPtr);
        // TODO: are there any checks on serialPtr other than being +ve?

        NodePtr sigAlgoPtr = certificate.nextSiblingOf(serialPtr);
        require(
            certificate.keccak(sigAlgoPtr.content(), sigAlgoPtr.length()) == CERT_ALGO_OID, "invalid cert sig algo"
        );

        return _parseTbs2(certificate, sigAlgoPtr);
    }

    function _parseTbs2(bytes memory certificate, NodePtr sigAlgoPtr) internal view returns (uint256, bytes memory) {
        NodePtr issuerPtr = certificate.nextSiblingOf(sigAlgoPtr);
        // TODO: add checks on issuer

        NodePtr validityPtr = certificate.nextSiblingOf(issuerPtr);
        NodePtr notBeforePtr = certificate.firstChildOf(validityPtr);
        uint256 notBefore = certificate.timestampAt(notBeforePtr);
        require(notBefore <= block.timestamp, "certificate not valid yet");
        NodePtr notAfterPtr = certificate.nextSiblingOf(notBeforePtr);
        uint256 notAfter = certificate.timestampAt(notAfterPtr);
        require(notAfter >= block.timestamp, "certificate not valid anymore");

        NodePtr subjectPtr = certificate.nextSiblingOf(validityPtr);
        // TODO: are there any checks on subject
        // TODO: need to check if issuer of this cert is the parent cert

        return (notAfter, _verifyTbs2(certificate, certificate.nextSiblingOf(subjectPtr)));
    }

    function _verifyTbs2(bytes memory certificate, NodePtr subjectPublicKeyInfoPtr)
        internal
        pure
        returns (bytes memory)
    {
        NodePtr pubKeyAlgoPtr = certificate.firstChildOf(subjectPublicKeyInfoPtr);
        NodePtr pubKeyAlgoIdPtr = certificate.firstChildOf(pubKeyAlgoPtr);
        require(
            certificate.keccak(pubKeyAlgoIdPtr.content(), pubKeyAlgoIdPtr.length()) == EC_PUB_KEY_OID,
            "invalid cert algo id"
        );

        NodePtr algoParamsPtr = certificate.nextSiblingOf(pubKeyAlgoIdPtr);
        require(
            certificate.keccak(algoParamsPtr.content(), algoParamsPtr.length()) == SECP_384_R1_OID,
            "invalid cert algo param"
        );

        NodePtr subjectPublicKeyPtr = certificate.nextSiblingOf(pubKeyAlgoPtr);
        NodePtr subjectPubKeyPtr = certificate.bitstringAt(subjectPublicKeyPtr);
        uint256 end = subjectPubKeyPtr.content() + subjectPubKeyPtr.length();
        bytes memory subjectPubKey = certificate.slice(end - 96, end);

        // NodePtr extensionsPtr = certificate.nextSiblingOf(subjectPublicKeyInfoPtr);
        // TODO: verify extensions based on 3.2.3.2 section in https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#32-syntactical-validation

        return subjectPubKey;
    }

    function verifySignature(bytes memory pubKey, bytes memory hash, bytes memory sig) internal view {
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
