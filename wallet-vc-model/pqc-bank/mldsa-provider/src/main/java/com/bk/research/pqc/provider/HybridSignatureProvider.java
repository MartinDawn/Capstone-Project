package com.bk.research.pqc.provider;

import com.bk.research.pqc.HybridConfig;
import com.bk.research.pqc.HybridKeyManager;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

import java.security.Signature;

public class HybridSignatureProvider implements SignatureProvider {

    private final KeycloakSession session;
    private final String algorithmId;

    public HybridSignatureProvider(KeycloakSession session, String algorithmId) {
        this.session = session;
        this.algorithmId = algorithmId != null ? algorithmId : "ES384";
    }

    @Override
    public SignatureSignerContext signer() throws SignatureException {
        return createSignerContext("hybrid-" + algorithmId.toLowerCase() + "-kid");
    }

    @Override
    public SignatureSignerContext signer(KeyWrapper key) throws SignatureException {
        return createSignerContext(key.getKid());
    }

    private SignatureSignerContext createSignerContext(String kid) {
        return new SignatureSignerContext() {
            @Override
            public String getKid() {
                return kid;
            }

            @Override
            public String getAlgorithm() {
                return algorithmId; // Classical algorithm ID (e.g. ES384) in JWS Header
            }

            @Override
            public String getHashAlgorithm() {
                if ("ES384".equals(algorithmId)) return "SHA-384";
                if ("ES256".equals(algorithmId)) return "SHA-256";
                if ("PS256".equals(algorithmId)) return "SHA-256";
                return "SHA-384";
            }

            @Override
            public byte[] sign(byte[] data) throws SignatureException {
                try {
                    HybridConfig.PqcAlgorithm pqcConfig = HybridConfig.getAlgorithm();

                    if (pqcConfig.isClassical()) {
                        Signature classicalSigner = getClassicalSignatureInstance();
                        classicalSigner.initSign(HybridKeyManager.getInstance().getClassicalKeyPair(algorithmId).getPrivate());
                        classicalSigner.update(data);
                        return classicalSigner.sign();
                    }

                    // Native IETF Composite Signature: MLDSA65-ECDSA-P384-SHA512 using Bouncy Castle 1.85
                    Signature compositeSigner = Signature.getInstance(HybridKeyManager.COMPOSITE_ALG, "BC");
                    compositeSigner.initSign(HybridKeyManager.getInstance().getCompositeKeyPair().getPrivate());
                    compositeSigner.update(data);
                    return compositeSigner.sign();

                } catch (Exception e) {
                    throw new SignatureException("Failed to generate composite signature: " + e.getMessage(), e);
                }
            }
        };
    }

    private Signature getClassicalSignatureInstance() throws Exception {
        if ("ES384".equals(algorithmId)) return Signature.getInstance("SHA384withECDSAinP1363Format");
        if ("ES256".equals(algorithmId)) return Signature.getInstance("SHA256withECDSAinP1363Format");
        if ("PS256".equals(algorithmId)) return Signature.getInstance("SHA256withRSA/PSS");
        return Signature.getInstance("SHA384withECDSAinP1363Format");
    }

    @Override
    public SignatureVerifierContext verifier(String kid) throws VerificationException {
        return createVerifierContext(kid);
    }

    @Override
    public SignatureVerifierContext verifier(KeyWrapper key) throws VerificationException {
        return createVerifierContext(key.getKid());
    }

    private SignatureVerifierContext createVerifierContext(String kid) {
        return new SignatureVerifierContext() {
            @Override
            public String getKid() {
                return kid;
            }

            @Override
            public String getAlgorithm() {
                return algorithmId;
            }

            @Override
            public boolean verify(byte[] data, byte[] signature) throws SignatureException {
                try {
                    Signature compositeVerifier = Signature.getInstance(HybridKeyManager.COMPOSITE_ALG, "BC");
                    compositeVerifier.initVerify(HybridKeyManager.getInstance().getCompositeKeyPair().getPublic());
                    compositeVerifier.update(data);
                    return compositeVerifier.verify(signature);
                } catch (Exception e) {
                    throw new SignatureException("Failed to verify hybrid signature: " + e.getMessage(), e);
                }
            }
        };
    }

    @Override
    public boolean isAsymmetricAlgorithm() {
        return true;
    }
}
