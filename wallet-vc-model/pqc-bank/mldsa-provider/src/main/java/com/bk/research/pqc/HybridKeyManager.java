package com.bk.research.pqc;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.CompositePrivateKey;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.logging.Logger;

public class HybridKeyManager {
    
    private static final Logger logger = Logger.getLogger(HybridKeyManager.class.getName());
    public static final String COMPOSITE_ALG = "MLDSA65-ECDSA-P384-SHA512";
    
    private static final HybridKeyManager instance = new HybridKeyManager();
    
    private KeyPair compositeKeyPair;
    private KeyPair classicalKeyPairES384;
    private KeyPair classicalKeyPairES256;
    private KeyPair classicalKeyPairPS256;
    private String compositePublicKeyBase64;

    private HybridKeyManager() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        generateKeys();
    }

    public static HybridKeyManager getInstance() {
        return instance;
    }

    private void generateKeys() {
        try {
            // Generate Composite KeyPair (MLDSA65-ECDSA-P384-SHA512) using Bouncy Castle 1.85
            KeyPairGenerator compositeGen = KeyPairGenerator.getInstance(COMPOSITE_ALG, "BC");
            compositeKeyPair = compositeGen.generateKeyPair();

            compositePublicKeyBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    compositeKeyPair.getPublic().getEncoded());

            // Extract or generate classical ES384 key pair for Keycloak standard JWKS / compatibility
            if (compositeKeyPair.getPublic() instanceof CompositePublicKey && compositeKeyPair.getPrivate() instanceof CompositePrivateKey) {
                CompositePublicKey cpk = (CompositePublicKey) compositeKeyPair.getPublic();
                CompositePrivateKey cpr = (CompositePrivateKey) compositeKeyPair.getPrivate();
                // Index 0: ML-DSA-65, Index 1: EC (secp384r1)
                classicalKeyPairES384 = new KeyPair(cpk.getPublicKeys().get(1), cpr.getPrivateKeys().get(1));
            } else {
                KeyPairGenerator ecGen384 = KeyPairGenerator.getInstance("EC");
                ecGen384.initialize(new ECGenParameterSpec("secp384r1"), new SecureRandom());
                classicalKeyPairES384 = ecGen384.generateKeyPair();
            }

            // Generate Classical ES256 (secp256r1) for backward compatibility
            KeyPairGenerator ecGen256 = KeyPairGenerator.getInstance("EC");
            ecGen256.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            classicalKeyPairES256 = ecGen256.generateKeyPair();
            
            // Generate Classical PS256 (RSA 2048) for legacy fallback
            KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
            rsaGen.initialize(2048, new SecureRandom());
            classicalKeyPairPS256 = rsaGen.generateKeyPair();
            
            logger.info("HybridKeyManager initialized successfully with BC 1.85 Composite MLDSA65-ECDSA-P384-SHA512.");
        } catch (Exception e) {
            logger.severe("Failed to generate keys for HybridKeyManager: " + e.getMessage());
            throw new RuntimeException("Failed to generate keys", e);
        }
    }

    public KeyPair getCompositeKeyPair() {
        return compositeKeyPair;
    }

    public KeyPair getClassicalKeyPair(String algorithmId) {
        if ("ES384".equals(algorithmId)) return classicalKeyPairES384;
        if ("ES256".equals(algorithmId)) return classicalKeyPairES256;
        if ("PS256".equals(algorithmId)) return classicalKeyPairPS256;
        return classicalKeyPairES384;
    }

    public String getCompositePublicKeyBase64() {
        return compositePublicKeyBase64;
    }

    public String getPqcPublicKeyBase64() {
        return compositePublicKeyBase64;
    }
}
