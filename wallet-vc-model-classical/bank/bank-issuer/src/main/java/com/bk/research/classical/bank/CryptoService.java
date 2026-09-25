package com.bk.research.classical.bank;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

@Service
public class CryptoService {

    private ECKey ecJwk;
    private KeyPair ecKeyPair;
    private String bankKeyId;

    @PostConstruct
    public void initKeys() throws Exception {
        Path keyPath = Path.of(System.getenv().getOrDefault(
                "SIGNING_KEY_STORE_PATH", "/app/state/bank-signing-jwk.json"));
        if (Files.exists(keyPath)) {
            ecJwk = ECKey.parse(Files.readString(keyPath));
            bankKeyId = ecJwk.getKeyID();
            ecKeyPair = ecJwk.toKeyPair();
            System.out.println("[Bank CryptoService] Loaded durable Classical signing key. Bank Key ID: " + bankKeyId);
            return;
        }
        bankKeyId = "bank-classical-key-" + UUID.randomUUID().toString().substring(0, 8);

        // Generate ECDSA KeyPair on NIST P-256 (secp256r1) using Nimbus
        ecJwk = new ECKeyGenerator(Curve.P_256)
                .keyID(bankKeyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        ecKeyPair = ecJwk.toKeyPair();

        Files.createDirectories(keyPath.getParent());
        Path temporaryPath = keyPath.resolveSibling(keyPath.getFileName() + ".tmp");
        Files.writeString(temporaryPath, ecJwk.toJSONString());
        try {
            Files.move(temporaryPath, keyPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
            Files.move(temporaryPath, keyPath, StandardCopyOption.REPLACE_EXISTING);
        }

        System.out.println("[Bank CryptoService] Classical ECDSA P-256 keypair generated. Bank Key ID: " + bankKeyId);
    }

    public ECKey getEcJwk() {
        return ecJwk;
    }

    public String getBankKeyId() {
        return bankKeyId;
    }

    public String getAlgorithm() {
        return "ES256";
    }

    /**
     * Sign payload with ECDSA P-256 (ES256)
     */
    public String sign(String payloadJson, String typ) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(typ))
                .keyID(bankKeyId)
                .build();
        Payload payload = new Payload(payloadJson);

        JWSObject jwsObject = new JWSObject(header, payload);
        JWSSigner signer = new ECDSASigner((ECPrivateKey) ecKeyPair.getPrivate());
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public static byte[] concatToDer(byte[] concat) {
        if (concat == null) return new byte[0];
        if (concat.length != 64 && concat.length != 96) return concat;
        try {
            int len = concat.length / 2;
            byte[] r = new byte[len];
            byte[] s = new byte[len];
            System.arraycopy(concat, 0, r, 0, len);
            System.arraycopy(concat, len, s, 0, len);

            java.math.BigInteger rInt = new java.math.BigInteger(1, r);
            java.math.BigInteger sInt = new java.math.BigInteger(1, s);

            byte[] rBytes = rInt.toByteArray();
            byte[] sBytes = sInt.toByteArray();

            int innerLen = 2 + rBytes.length + 2 + sBytes.length;
            byte[] der;
            int offset = 0;
            if (innerLen < 128) {
                der = new byte[2 + innerLen];
                der[offset++] = 0x30;
                der[offset++] = (byte) innerLen;
            } else {
                der = new byte[3 + innerLen];
                der[offset++] = 0x30;
                der[offset++] = (byte) 0x81;
                der[offset++] = (byte) innerLen;
            }
            der[offset++] = 0x02;
            der[offset++] = (byte) rBytes.length;
            System.arraycopy(rBytes, 0, der, offset, rBytes.length);
            offset += rBytes.length;
            der[offset++] = 0x02;
            der[offset++] = (byte) sBytes.length;
            System.arraycopy(sBytes, 0, der, offset, sBytes.length);
            return der;
        } catch (Exception ex) {
            return concat;
        }
    }

    /**
     * Verify ECDSA signature against given public key (supports both JWS P1363 and DER formats)
     */
    public boolean verifySignature(String signingInput, byte[] sigBytes, ECPublicKey ecPublicKey) {
        try {
            if (ecPublicKey == null || sigBytes == null) return false;
            byte[] derSig = (sigBytes.length == 64 || sigBytes.length == 96) ? concatToDer(sigBytes) : sigBytes;
            int keySize = (ecPublicKey.getParams() != null && ecPublicKey.getParams().getCurve() != null)
                    ? ecPublicKey.getParams().getCurve().getField().getFieldSize()
                    : 256;
            String alg = (keySize == 384) ? "SHA384withECDSA" : (keySize == 521) ? "SHA512withECDSA" : "SHA256withECDSA";
            Signature ecVerifier = Signature.getInstance(alg);
            ecVerifier.initVerify(ecPublicKey);
            ecVerifier.update(signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return ecVerifier.verify(derSig);
        } catch (Exception e) {
            System.err.println("[CryptoService] Verification failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Decrypt DAS-only JWE package using Bank private EC key (ECDH-ES + A256GCM per F3-03 / F4-07)
     */
    public String decryptDasPackage(String jweString) throws Exception {
        if (jweString == null || jweString.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty JWE string");
        }
        com.nimbusds.jose.JWEObject jweObject = com.nimbusds.jose.JWEObject.parse(jweString.trim());
        jweObject.decrypt(new com.nimbusds.jose.crypto.ECDHDecrypter((ECPrivateKey) ecKeyPair.getPrivate()));
        return jweObject.getPayload().toString();
    }

    /**
     * Encrypt sensitive claims into JWE ECDH-ES + A256GCM to Bank recipient EC key
     */
    public static String encryptForBank(String payloadJson, ECPublicKey bankPubKey, String keyId) throws Exception {
        com.nimbusds.jose.JWEHeader header = new com.nimbusds.jose.JWEHeader.Builder(
                com.nimbusds.jose.JWEAlgorithm.ECDH_ES, com.nimbusds.jose.EncryptionMethod.A256GCM)
                .keyID(keyId)
                .build();
        com.nimbusds.jose.JWEObject jweObject = new com.nimbusds.jose.JWEObject(header, new com.nimbusds.jose.Payload(payloadJson));
        jweObject.encrypt(new com.nimbusds.jose.crypto.ECDHEncrypter(bankPubKey));
        return jweObject.serialize();
    }
}
