// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Sha2Ext} from "./Sha2Ext.sol";
import {Asn1Decode, Asn1Ptr, LibAsn1Ptr} from "./Asn1Decode.sol";
import {ECDSA384} from "@solarity/libs/crypto/ECDSA384.sol";
import {ECDSA384Curve} from "./ECDSA384Curve.sol";
import {LibBytes} from "./LibBytes.sol";
import {ICertManager} from "./ICertManager.sol";

// adapted from https://github.com/marlinprotocol/NitroProver/blob/f1d368d1f172ad3a55cd2aaaa98ad6a6e7dcde9d/src/CertManager.sol

contract CertManager is ICertManager {
    using Asn1Decode for bytes;
    using LibAsn1Ptr for Asn1Ptr;
    using LibBytes for bytes;

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

    // extension OID certificate constants
    bytes32 public constant BASIC_CONSTRAINTS_OID = keccak256(hex"551d13");
    bytes32 public constant KEY_USAGE_OID = keccak256(hex"551d0f");

    // certHash -> CachedCert
    mapping(bytes32 => bytes) public verified;

    constructor() {
        CachedCert memory empty;
        _verifyCert(ROOT_CA_CERT, ROOT_CA_CERT_HASH, false, empty);
    }

    function verifyCert(bytes memory cert, bool clientCert, bytes32 parentCertHash)
        external
        returns (CachedCert memory)
    {
        bytes memory parentCacheBytes = verified[parentCertHash];
        require(parentCacheBytes.length != 0, "parent cert unverified");
        CachedCert memory parentCache = abi.decode(parentCacheBytes, (CachedCert));
        require(parentCache.notAfter >= block.timestamp, "parent cert expired");
        bytes32 certHash = keccak256(cert);
        require(verified[certHash].length == 0, "cert already verified");
        return _verifyCert(cert, certHash, clientCert, parentCache);
    }

    function verifyCertBundle(bytes memory certificate, bytes[] calldata cabundle)
        external
        returns (CachedCert memory)
    {
        CachedCert memory parentCache;
        for (uint256 i = 0; i < cabundle.length; i++) {
            bytes32 certHash = keccak256(cabundle[i]);
            require(i > 0 || certHash == ROOT_CA_CERT_HASH, "Root CA cert not matching");
            parentCache = _verifyCert(cabundle[i], certHash, false, parentCache);
        }
        return _verifyCert(certificate, keccak256(certificate), true, parentCache);
    }

    function _verifyCert(bytes memory certificate, bytes32 certHash, bool clientCert, CachedCert memory parentCache)
        internal
        returns (CachedCert memory)
    {
        // skip verification if already verified
        bytes memory cacheBytes = verified[certHash];
        CachedCert memory cache;
        if (cacheBytes.length != 0) {
            cache = abi.decode(cacheBytes, (CachedCert));
            require(cache.notAfter >= block.timestamp, "cert expired");
            return cache;
        }

        Asn1Ptr root = certificate.root();
        Asn1Ptr tbsCertPtr = certificate.firstChildOf(root);
        (uint256 notAfter, int256 maxPathLen, bytes memory pubKey) = _parseTbs(certificate, tbsCertPtr, clientCert);

        if (parentCache.pubKey.length != 0 || certHash != ROOT_CA_CERT_HASH) {
            if (parentCache.maxPathLen > 0 && (maxPathLen < 0 || maxPathLen >= parentCache.maxPathLen)) {
                maxPathLen = parentCache.maxPathLen - 1;
            }
            require((parentCache.maxPathLen == 0) == clientCert, "maxPathLen exceeded");
            _verifyCertSignature(certificate, tbsCertPtr, parentCache.pubKey);
        }

        cache = CachedCert({notAfter: notAfter, maxPathLen: maxPathLen, pubKey: pubKey});
        verified[certHash] = abi.encode(cache);
        return cache;
    }

    function _parseTbs(bytes memory certificate, Asn1Ptr ptr, bool clientCert)
        internal
        view
        returns (uint256 notAfter, int256 maxPathLen, bytes memory pubKey)
    {
        Asn1Ptr versionPtr = certificate.firstChildOf(ptr);
        Asn1Ptr vPtr = certificate.firstChildOf(versionPtr);
        Asn1Ptr serialPtr = certificate.nextSiblingOf(versionPtr);
        Asn1Ptr sigAlgoPtr = certificate.nextSiblingOf(serialPtr);

        require(certificate.keccak(sigAlgoPtr.content(), sigAlgoPtr.length()) == CERT_ALGO_OID, "invalid cert sig algo");
        uint256 version = certificate.uintAt(vPtr);
        // as extensions are used in cert, version should be 3 (value 2) as per https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1
        require(version == 2, "version should be 3");

        (notAfter, maxPathLen, pubKey) = _parseTbsInner(certificate, sigAlgoPtr, clientCert);
    }

    function _parseTbsInner(bytes memory certificate, Asn1Ptr sigAlgoPtr, bool clientCert)
        internal
        view
        returns (uint256 notAfter, int256 maxPathLen, bytes memory pubKey)
    {
        Asn1Ptr issuerPtr = certificate.nextSiblingOf(sigAlgoPtr);
        Asn1Ptr validityPtr = certificate.nextSiblingOf(issuerPtr);
        Asn1Ptr subjectPtr = certificate.nextSiblingOf(validityPtr);
        Asn1Ptr subjectPublicKeyInfoPtr = certificate.nextSiblingOf(subjectPtr);
        Asn1Ptr extensionsPtr = certificate.nextSiblingOf(subjectPublicKeyInfoPtr);

        if (certificate[extensionsPtr.header()] == 0x81) {
            // skip optional issuerUniqueID
            extensionsPtr = certificate.nextSiblingOf(extensionsPtr);
        }
        if (certificate[extensionsPtr.header()] == 0x82) {
            // skip optional subjectUniqueID
            extensionsPtr = certificate.nextSiblingOf(extensionsPtr);
        }

        notAfter = _verifyValidity(certificate, validityPtr);
        maxPathLen = _verifyExtensions(certificate, extensionsPtr, clientCert);
        pubKey = _parsePubKey(certificate, subjectPublicKeyInfoPtr);
    }

    function _parsePubKey(bytes memory certificate, Asn1Ptr subjectPublicKeyInfoPtr)
        internal
        pure
        returns (bytes memory subjectPubKey)
    {
        Asn1Ptr pubKeyAlgoPtr = certificate.firstChildOf(subjectPublicKeyInfoPtr);
        Asn1Ptr pubKeyAlgoIdPtr = certificate.firstChildOf(pubKeyAlgoPtr);
        Asn1Ptr algoParamsPtr = certificate.nextSiblingOf(pubKeyAlgoIdPtr);
        Asn1Ptr subjectPublicKeyPtr = certificate.nextSiblingOf(pubKeyAlgoPtr);
        Asn1Ptr subjectPubKeyPtr = certificate.bitstring(subjectPublicKeyPtr);

        require(
            certificate.keccak(pubKeyAlgoIdPtr.content(), pubKeyAlgoIdPtr.length()) == EC_PUB_KEY_OID,
            "invalid cert algo id"
        );
        require(
            certificate.keccak(algoParamsPtr.content(), algoParamsPtr.length()) == SECP_384_R1_OID,
            "invalid cert algo param"
        );

        uint256 end = subjectPubKeyPtr.content() + subjectPubKeyPtr.length();
        subjectPubKey = certificate.slice(end - 96, 96);
    }

    function _verifyValidity(bytes memory certificate, Asn1Ptr validityPtr) internal view returns (uint256 notAfter) {
        Asn1Ptr notBeforePtr = certificate.firstChildOf(validityPtr);
        Asn1Ptr notAfterPtr = certificate.nextSiblingOf(notBeforePtr);

        uint256 notBefore = certificate.timestampAt(notBeforePtr);
        notAfter = certificate.timestampAt(notAfterPtr);

        require(notBefore <= block.timestamp, "certificate not valid yet");
        require(notAfter >= block.timestamp, "certificate not valid anymore");
    }

    function _verifyExtensions(bytes memory certificate, Asn1Ptr extensionsPtr, bool clientCert)
        internal
        pure
        returns (int256 maxPathLen)
    {
        require(certificate[extensionsPtr.header()] == 0xa3, "invalid extensions");
        extensionsPtr = certificate.firstChildOf(extensionsPtr);
        Asn1Ptr extensionPtr = certificate.firstChildOf(extensionsPtr);
        uint256 end = extensionsPtr.content() + extensionsPtr.length();
        bool basicConstraintsFound = false;
        bool keyUsageFound = false;
        maxPathLen = -1;

        while (true) {
            Asn1Ptr oidPtr = certificate.firstChildOf(extensionPtr);
            bytes32 oid = certificate.keccak(oidPtr.content(), oidPtr.length());

            if (oid == BASIC_CONSTRAINTS_OID || oid == KEY_USAGE_OID) {
                Asn1Ptr valuePtr = certificate.nextSiblingOf(oidPtr);

                if (certificate[valuePtr.header()] == 0x01) {
                    // skip optional critical bool
                    require(valuePtr.length() == 1, "invalid critical bool value");
                    valuePtr = certificate.nextSiblingOf(valuePtr);
                }

                valuePtr = certificate.octetString(valuePtr);

                if (oid == BASIC_CONSTRAINTS_OID) {
                    basicConstraintsFound = true;
                    maxPathLen = _verifyBasicConstraintsExtension(certificate, valuePtr);
                } else {
                    keyUsageFound = true;
                    _verifyKeyUsageExtension(certificate, valuePtr, clientCert);
                }
            }

            if (extensionPtr.content() + extensionPtr.length() == end) {
                break;
            }
            extensionPtr = certificate.nextSiblingOf(extensionPtr);
        }

        require(basicConstraintsFound, "basicConstraints not found");
        require(keyUsageFound, "keyUsage not found");
        require(!clientCert || maxPathLen == -1, "maxPathLen must be undefined for client cert");
    }

    function _verifyBasicConstraintsExtension(bytes memory certificate, Asn1Ptr valuePtr)
        internal
        pure
        returns (int256 maxPathLen)
    {
        maxPathLen = -1;
        Asn1Ptr basicConstraintsPtr = certificate.firstChildOf(valuePtr);
        if (certificate[basicConstraintsPtr.header()] == 0x01) {
            // skip optional isCA bool
            require(basicConstraintsPtr.length() == 1, "invalid isCA bool value");
            basicConstraintsPtr = certificate.nextSiblingOf(basicConstraintsPtr);
        }
        if (certificate[basicConstraintsPtr.header()] == 0x02) {
            maxPathLen = int256(certificate.uintAt(basicConstraintsPtr));
        }
    }

    function _verifyKeyUsageExtension(bytes memory certificate, Asn1Ptr valuePtr, bool clientCert) internal pure {
        uint256 value = certificate.bitstringUintAt(valuePtr);
        // bits are reversed (DigitalSignature 0x01 => 0x80, CertSign 0x32 => 0x04)
        if (clientCert) {
            require(value & 0x80 == 0x80, "DigitalSignature must be present");
        } else {
            require(value & 0x04 == 0x04, "CertSign must be present");
        }
    }

    function _verifyCertSignature(bytes memory certificate, Asn1Ptr ptr, bytes memory pubKey) internal view {
        Asn1Ptr sigAlgoPtr = certificate.nextSiblingOf(ptr);
        require(certificate.keccak(sigAlgoPtr.content(), sigAlgoPtr.length()) == CERT_ALGO_OID, "invalid cert sig algo");

        bytes memory hash = Sha2Ext.sha384(certificate, ptr.header(), ptr.totalLength());

        Asn1Ptr sigPtr = certificate.nextSiblingOf(sigAlgoPtr);
        Asn1Ptr sigBPtr = certificate.bitstring(sigPtr);
        Asn1Ptr sigRoot = certificate.rootOf(sigBPtr);
        Asn1Ptr sigRPtr = certificate.firstChildOf(sigRoot);
        Asn1Ptr sigSPtr = certificate.nextSiblingOf(sigRPtr);
        (uint128 rhi, uint256 rlo) = certificate.uint384At(sigRPtr);
        (uint128 shi, uint256 slo) = certificate.uint384At(sigSPtr);
        bytes memory sigPacked = abi.encodePacked(rhi, rlo, shi, slo);

        _verifySignature(pubKey, hash, sigPacked);
    }

    function _verifySignature(bytes memory pubKey, bytes memory hash, bytes memory sig) internal view {
        require(ECDSA384.verify(ECDSA384Curve.p384(), hash, sig, pubKey), "invalid sig");
    }
}
