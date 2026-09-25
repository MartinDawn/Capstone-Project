package com.bk.research.pqc.tpp;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

@Service
public class CryptoService {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static final String COMPOSITE_ALG = "MLDSA65-ECDSA-P384-SHA512";

    private KeyPair compositeKeyPair;
    private ECKey ecJwk;
    private KeyPair ecKeyPair;
    private String walletKeyId;
    private String compositePublicKeyBase64;

    @PostConstruct
    public void initKeys() throws Exception {
        walletKeyId = "tpp-key-" + UUID.randomUUID().toString().substring(0, 8);

        // 1. Classical EC KeyPair (secp384r1 / P-384) using Nimbus for legacy/JWK
        ecJwk = new ECKeyGenerator(Curve.P_384)
                .keyID(walletKeyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES384)
                .generate();
        ecKeyPair = ecJwk.toKeyPair();

        // 2. Standard IETF Composite KeyPair (MLDSA65-ECDSA-P384-SHA512) via Bouncy Castle 1.84
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(COMPOSITE_ALG, "BC");
        compositeKeyPair = kpg.generateKeyPair();
        byte[] pubBytes = compositeKeyPair.getPublic().getEncoded();
        compositePublicKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pubBytes);

        System.out.println("[TPP CryptoService] Bouncy Castle 1.84 Composite " + COMPOSITE_ALG + " ready. Key ID: " + walletKeyId);
    }

    public ECKey getEcJwk() {
        return ecJwk;
    }

    public KeyPair getCompositeKeyPair() {
        return compositeKeyPair;
    }

    public PublicKey getCompositePublicKey() {
        return compositeKeyPair.getPublic();
    }

    public String getCompositePublicKeyBase64() {
        return compositePublicKeyBase64;
    }

    public String getPqcPublicKeyBase64() {
        return compositePublicKeyBase64;
    }

    public String signHybrid(String payloadJson, String typ) throws Exception {
        JWSHeader header = new JWSHeader.Builder(new JWSAlgorithm(COMPOSITE_ALG))
                .type(new JOSEObjectType(typ))
                .keyID(walletKeyId)
                .customParam("pqc_alg", "p384_mldsa65")
                .build();
        Payload payload = new Payload(payloadJson);

        String headerB64 = header.toBase64URL().toString();
        String payloadB64 = payload.toBase64URL().toString();
        String signingInput = headerB64 + "." + payloadB64;

        // Native IETF Composite Signature using Bouncy Castle 1.84
        Signature signer = Signature.getInstance(COMPOSITE_ALG, "BC");
        signer.initSign(compositeKeyPair.getPrivate());
        signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
        byte[] compositeSigBytes = signer.sign();

        String compositeSigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(compositeSigBytes);
        return signingInput + "." + compositeSigB64;
    }

    public String signClassical(String payloadJson, String typ) throws Exception {
        return signHybrid(payloadJson, typ);
    }

    public boolean verifySignature(String jwtStr, ECKey publicKey) {
        try {
            if (jwtStr == null || publicKey == null) return false;
            String jwtPart = jwtStr.split("~")[0];
            JWSObject jwsObject = JWSObject.parse(jwtPart);
            return jwsObject.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(publicKey.toECPublicKey()));
        } catch (Exception e) {
            return false;
        }
    }

    public boolean verifyHybridSignature(String signingInput, byte[] sigBytes,
                                         ECPublicKey ecPublicKey, byte[] pqcPublicKey, String pqcAlg) {
        if (sigBytes == null || sigBytes.length == 0) {
            System.err.println("[TPP CryptoService] PQC signature verification rejected: empty signature bytes");
            return false;
        }

        // Strict Native IETF Composite Signature (MLDSA65-ECDSA-P384-SHA512)
        if (pqcPublicKey == null || pqcPublicKey.length == 0) {
            System.err.println("[TPP CryptoService] PQC signature verification rejected: missing mandatory PQC composite public key");
            return false;
        }

        try {
            KeyFactory kf = KeyFactory.getInstance(COMPOSITE_ALG, "BC");
            PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pqcPublicKey));
            Signature verifier = Signature.getInstance(COMPOSITE_ALG, "BC");
            verifier.initVerify(pubKey);
            verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
            boolean verified = verifier.verify(sigBytes);
            if (!verified) {
                System.err.println("[TPP CryptoService] PQC composite signature verification failed (invalid signature)");
            }
            return verified;
        } catch (Exception e) {
            System.err.println("[TPP CryptoService] Error during PQC composite signature verification: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] concatToDer(byte[] concat) {
        if (concat == null) return new byte[0];
        if (concat.length != 64 && concat.length != 96) return concat;
        try {
            int len = concat.length / 2;
            byte[] r = Arrays.copyOfRange(concat, 0, len);
            byte[] s = Arrays.copyOfRange(concat, len, concat.length);

            int rPad = (r[0] < 0) ? 1 : 0;
            int sPad = (s[0] < 0) ? 1 : 0;

            int rLen = len + rPad;
            int sLen = len + sPad;
            int totalLen = 2 + rLen + 2 + sLen;

            byte[] der = new byte[2 + totalLen];
            int idx = 0;
            der[idx++] = 0x30;
            der[idx++] = (byte) totalLen;

            der[idx++] = 0x02;
            der[idx++] = (byte) rLen;
            if (rPad > 0) der[idx++] = 0x00;
            System.arraycopy(r, 0, der, idx, len);
            idx += len;

            der[idx++] = 0x02;
            der[idx++] = (byte) sLen;
            if (sPad > 0) der[idx++] = 0x00;
            System.arraycopy(s, 0, der, idx, len);

            return der;
        } catch (Exception e) {
            return concat;
        }
    }
}
