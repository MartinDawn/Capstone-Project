package com.bk.research.pqc.bank;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
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
    private KeyPair kemKeyPair;
    private ECKey ecJwk;
    private KeyPair ecKeyPair;
    private String bankKeyId;
    private String compositePublicKeyBase64;
    private String pqcKemPublicKeyBase64;

    @PostConstruct
    public void initKeys() throws Exception {
        Path keyPath = Path.of(System.getenv().getOrDefault(
                "SIGNING_KEY_STORE_PATH", "/app/state/bank-hybrid-signing-key.json"));
        if (Files.exists(keyPath)) {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(keyPath.toFile());
            ecJwk = ECKey.parse(root.get("ec_jwk").asText());
            ecKeyPair = ecJwk.toKeyPair();
            bankKeyId = ecJwk.getKeyID();
            KeyFactory compositeFactory = KeyFactory.getInstance(COMPOSITE_ALG, "BC");
            compositeKeyPair = new KeyPair(
                    compositeFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(root.get("composite_public").asText()))),
                    compositeFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(root.get("composite_private").asText()))));
            KeyFactory kemFactory = KeyFactory.getInstance("ML-KEM", "BC");
            kemKeyPair = new KeyPair(
                    kemFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(root.get("kem_public").asText()))),
                    kemFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(root.get("kem_private").asText()))));
            compositePublicKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(compositeKeyPair.getPublic().getEncoded());
            pqcKemPublicKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(kemKeyPair.getPublic().getEncoded());
            System.out.println("[Bank CryptoService] Loaded durable hybrid signing and KEM keys. Bank Key ID: " + bankKeyId);
            return;
        }
        initEphemeralKeys();

        Files.createDirectories(keyPath.getParent());
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        root.put("ec_jwk", ecJwk.toJSONString());
        root.put("composite_public", Base64.getEncoder().encodeToString(compositeKeyPair.getPublic().getEncoded()));
        root.put("composite_private", Base64.getEncoder().encodeToString(compositeKeyPair.getPrivate().getEncoded()));
        root.put("kem_public", Base64.getEncoder().encodeToString(kemKeyPair.getPublic().getEncoded()));
        root.put("kem_private", Base64.getEncoder().encodeToString(kemKeyPair.getPrivate().getEncoded()));
        Path temporaryPath = keyPath.resolveSibling(keyPath.getFileName() + ".tmp");
        mapper.writerWithDefaultPrettyPrinter().writeValue(temporaryPath.toFile(), root);
        try {
            Files.move(temporaryPath, keyPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
            Files.move(temporaryPath, keyPath, StandardCopyOption.REPLACE_EXISTING);
        }

        System.out.println("[Bank CryptoService] Bouncy Castle Composite " + COMPOSITE_ALG + " and ML-KEM-768 ready. Bank Key ID: " + bankKeyId);
    }

    public void initEphemeralKeys() throws Exception {
        bankKeyId = "bank-hybrid-key-" + UUID.randomUUID().toString().substring(0, 8);

        // 1. Classical EC KeyPair (secp384r1 / P-384) for legacy/Nimbus support
        ecJwk = new ECKeyGenerator(Curve.P_384)
                .keyID(bankKeyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES384)
                .generate();
        ecKeyPair = ecJwk.toKeyPair();

        // 2. Standard IETF Composite KeyPair (MLDSA65-ECDSA-P384-SHA512) via Bouncy Castle
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(COMPOSITE_ALG, "BC");
        compositeKeyPair = kpg.generateKeyPair();
        byte[] pubBytes = compositeKeyPair.getPublic().getEncoded();
        compositePublicKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pubBytes);

        // 3. Post-Quantum KEM KeyPair (ML-KEM-768) via Bouncy Castle
        KeyPairGenerator kemKpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        kemKpg.initialize(org.bouncycastle.jcajce.spec.MLKEMParameterSpec.ml_kem_768);
        kemKeyPair = kemKpg.generateKeyPair();
        pqcKemPublicKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(
                kemKeyPair.getPublic().getEncoded());

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

    public String getPqcKemPublicKeyBase64() {
        return pqcKemPublicKeyBase64;
    }

    public String getBankKeyId() {
        return bankKeyId;
    }

    public String sign(String payloadJson, String typ) throws Exception {
        return signHybrid(payloadJson, typ);
    }

    public String signHybrid(String payloadJson, String typ) throws Exception {
        JWSHeader header = new JWSHeader.Builder(new JWSAlgorithm(COMPOSITE_ALG))
                .type(new JOSEObjectType(typ))
                .keyID(bankKeyId)
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
            ecVerifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return ecVerifier.verify(derSig);
        } catch (Exception e) {
            System.err.println("[CryptoService] ECDSA Verification failed: " + e.getMessage());
            return false;
        }
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
                                         ECPublicKey ecPublicKey, byte[] pqcPublicKeyBytes, String pqcAlg) {
        if (sigBytes == null || sigBytes.length == 0) {
            System.err.println("[CryptoService] PQC signature verification rejected: empty signature bytes");
            return false;
        }

        // Strict Native IETF Composite Signature (MLDSA65-ECDSA-P384-SHA512)
        if (pqcPublicKeyBytes == null || pqcPublicKeyBytes.length == 0) {
            System.err.println("[CryptoService] PQC signature verification rejected: missing mandatory PQC composite public key bytes");
            return false;
        }

        try {
            KeyFactory kf = KeyFactory.getInstance(COMPOSITE_ALG, "BC");
            PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pqcPublicKeyBytes));
            Signature verifier = Signature.getInstance(COMPOSITE_ALG, "BC");
            verifier.initVerify(pubKey);
            verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
            boolean verified = verifier.verify(sigBytes);
            if (!verified) {
                System.err.println("[CryptoService] PQC composite signature verification failed (invalid signature)");
            }
            return verified;
        } catch (Exception e) {
            System.err.println("[CryptoService] Error during PQC composite signature verification: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public PublicKey decodeCompositePublicKey(byte[] pubKeyBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance(COMPOSITE_ALG, "BC");
        return kf.generatePublic(new X509EncodedKeySpec(pubKeyBytes));
    }

    /**
     * Decrypt DAS-only package using ML-KEM-768 decapsulation + AES-256-GCM (F4-07)
     */
    public String decryptDasPackage(String pkgJsonStr) throws Exception {
        if (pkgJsonStr == null || pkgJsonStr.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty DAS package");
        }
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        com.fasterxml.jackson.databind.JsonNode node = mapper.readTree(pkgJsonStr.trim());

        String kemCtB64 = node.get("kem_ct").asText();
        String ivB64 = node.get("iv").asText();
        String ctB64 = node.get("ciphertext").asText();
        String tagB64 = node.has("tag") ? node.get("tag").asText() : "";

        byte[] kemCt = Base64.getDecoder().decode(kemCtB64);
        byte[] iv = Base64.getDecoder().decode(ivB64);
        byte[] ct = Base64.getDecoder().decode(ctB64);
        byte[] tag = tagB64.isEmpty() ? new byte[0] : Base64.getDecoder().decode(tagB64);

        // Real Bouncy Castle ML-KEM-768 decapsulation
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("ML-KEM", "BC");
        kg.init(new org.bouncycastle.jcajce.spec.KEMExtractSpec(kemKeyPair.getPrivate(), kemCt, "AES"));
        javax.crypto.SecretKey sharedSecret = (javax.crypto.SecretKey) kg.generateKey();

        byte[] combinedCtAndTag;
        if (tag.length > 0) {
            combinedCtAndTag = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, combinedCtAndTag, 0, ct.length);
            System.arraycopy(tag, 0, combinedCtAndTag, ct.length, tag.length);
        } else {
            combinedCtAndTag = ct;
        }

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.spec.GCMParameterSpec spec = new javax.crypto.spec.GCMParameterSpec(128, iv);
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, sharedSecret, spec);

        byte[] plaintext = cipher.doFinal(combinedCtAndTag);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * Encrypt sensitive claims into ML-KEM-768 + AES-256-GCM package
     */
    public static String encryptForBank(String payloadJson, String kemPubKeyB64, String recipientKid) throws Exception {
        byte[] pubBytes = Base64.getUrlDecoder().decode(kemPubKeyB64);
        KeyFactory kf = KeyFactory.getInstance("ML-KEM", "BC");
        PublicKey bankKemPub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));

        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("ML-KEM", "BC");
        kg.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec(bankKemPub, "AES"));
        org.bouncycastle.jcajce.SecretKeyWithEncapsulation secEnc = (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) kg.generateKey();
        byte[] kemCt = secEnc.getEncapsulation();
        javax.crypto.SecretKey sharedSecret = secEnc;

        byte[] iv = new byte[12];
        new java.security.SecureRandom().nextBytes(iv);

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.spec.GCMParameterSpec spec = new javax.crypto.spec.GCMParameterSpec(128, iv);
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, sharedSecret, spec);

        byte[] combined = cipher.doFinal(payloadJson.getBytes(StandardCharsets.UTF_8));
        int ctLen = combined.length - 16;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[16];
        System.arraycopy(combined, 0, ct, 0, ctLen);
        System.arraycopy(combined, ctLen, tag, 0, 16);

        org.json.JSONObject pkg = new org.json.JSONObject();
        pkg.put("alg", "ML-KEM-768+AES-256-GCM");
        pkg.put("kid", recipientKid);
        pkg.put("kem_ct", Base64.getEncoder().encodeToString(kemCt));
        pkg.put("iv", Base64.getEncoder().encodeToString(iv));
        pkg.put("ciphertext", Base64.getEncoder().encodeToString(ct));
        pkg.put("tag", Base64.getEncoder().encodeToString(tag));

        return pkg.toString();
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
}
