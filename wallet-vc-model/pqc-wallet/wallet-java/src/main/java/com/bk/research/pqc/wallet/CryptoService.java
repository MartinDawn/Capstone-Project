package com.bk.research.pqc.wallet;

import com.nimbusds.jose.*;
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
    private ECKey ecJwk;
    private KeyPair ecKeyPair;
    private String walletKeyId;
    private String compositePublicKeyBase64;

    @PostConstruct
    public void initKeys() throws Exception {
        Path keyPath = Path.of(System.getenv().getOrDefault(
                "SIGNING_KEY_STORE_PATH", "/app/state/wallet-hybrid-signing-key.json"));
        if (Files.exists(keyPath)) {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(keyPath.toFile());
            ecJwk = ECKey.parse(root.get("ec_jwk").asText());
            ecKeyPair = ecJwk.toKeyPair();
            walletKeyId = ecJwk.getKeyID();
            KeyFactory keyFactory = KeyFactory.getInstance(COMPOSITE_ALG, "BC");
            compositeKeyPair = new KeyPair(
                    keyFactory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(root.get("composite_public").asText()))),
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(root.get("composite_private").asText()))));
            compositePublicKeyBase64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(compositeKeyPair.getPublic().getEncoded());
            System.out.println("[Wallet CryptoService] Loaded durable hybrid signing key. Wallet Key ID: " + walletKeyId);
            return;
        }
        initEphemeralKeys();

        Files.createDirectories(keyPath.getParent());
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        root.put("ec_jwk", ecJwk.toJSONString());
        root.put("composite_public", Base64.getEncoder().encodeToString(compositeKeyPair.getPublic().getEncoded()));
        root.put("composite_private", Base64.getEncoder().encodeToString(compositeKeyPair.getPrivate().getEncoded()));
        Path temporaryPath = keyPath.resolveSibling(keyPath.getFileName() + ".tmp");
        mapper.writerWithDefaultPrettyPrinter().writeValue(temporaryPath.toFile(), root);
        try {
            Files.move(temporaryPath, keyPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
            Files.move(temporaryPath, keyPath, StandardCopyOption.REPLACE_EXISTING);
        }

        System.out.println("[Wallet CryptoService] Bouncy Castle 1.84 Composite " + COMPOSITE_ALG + " ready. Wallet Key ID: " + walletKeyId);
    }

    public void initEphemeralKeys() throws Exception {
        walletKeyId = "wallet-key-" + UUID.randomUUID().toString().substring(0, 8);

        // 1. Generate Classical EC KeyPair (secp384r1 / P-384) using Nimbus for legacy/JWK
        ecJwk = new ECKeyGenerator(Curve.P_384)
                .keyID(walletKeyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES384)
                .generate();
        ecKeyPair = ecJwk.toKeyPair();

        // 2. Generate Standard IETF Composite KeyPair (MLDSA65-ECDSA-P384-SHA512) via Bouncy Castle 1.84
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(COMPOSITE_ALG, "BC");
        compositeKeyPair = kpg.generateKeyPair();
        byte[] pubBytes = compositeKeyPair.getPublic().getEncoded();
        compositePublicKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(pubBytes);

    }

    public ECKey getEcJwk() {
        return ecJwk;
    }

    public String getWalletKeyId() {
        return walletKeyId;
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
        return signWithEncodedHeader(header.toBase64URL().toString(), payloadJson);
    }

    /**
     * Signs the OID4VCI proof-of-possession JWT. It is the only JWT that carries a public key in its header:
     * the issuer does not know the holder key yet, so the holder JWK (with the composite public key as a member
     * of that JWK) travels in the standard `jwk` header. Every other JWT is verified with a key the verifier
     * already trusts.
     */
    public String signProofHybrid(String payloadJson, String typ) throws Exception {
        ObjectMapper headerMapper = new ObjectMapper();
        ObjectNode holderJwk = (ObjectNode) headerMapper.readTree(ecJwk.toPublicJWK().toJSONString());
        holderJwk.put("composite_pub", compositePublicKeyBase64);
        ObjectNode header = headerMapper.createObjectNode();
        header.put("alg", COMPOSITE_ALG);
        header.put("typ", typ);
        header.put("kid", walletKeyId);
        header.put("pqc_alg", "p384_mldsa65");
        header.set("jwk", holderJwk);
        return signWithEncodedHeader(com.nimbusds.jose.util.Base64URL.encode(header.toString()).toString(), payloadJson);
    }

    private String signWithEncodedHeader(String headerB64, String payloadJson) throws Exception {
        Payload payload = new Payload(payloadJson);

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

    public boolean verifyCompositeSignature(String signingInput, byte[] sigBytes, byte[] pubKeyBytes) {
        try {
            KeyFactory kf = KeyFactory.getInstance(COMPOSITE_ALG, "BC");
            PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubKeyBytes));
            Signature verifier = Signature.getInstance(COMPOSITE_ALG, "BC");
            verifier.initVerify(pubKey);
            verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(sigBytes);
        } catch (Exception e) {
            return false;
        }
    }
}
