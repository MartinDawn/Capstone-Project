package com.bk.research.pqc.provider;

import com.bk.research.pqc.HybridKeyManager;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.ClientSignatureVerifierProvider;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Logger;

public class HybridClientSignatureVerifierProvider implements ClientSignatureVerifierProvider {

    private static final Logger logger = Logger.getLogger(HybridClientSignatureVerifierProvider.class.getName());
    private static final ObjectMapper mapper = new ObjectMapper();

    private final KeycloakSession session;
    private final String algorithmId;

    public HybridClientSignatureVerifierProvider(KeycloakSession session, String algorithmId) {
        this.session = session;
        this.algorithmId = algorithmId != null ? algorithmId : "ES384";
    }

    @Override
    public SignatureVerifierContext verifier(ClientModel client, JWSInput input) throws VerificationException {
        // No client authenticates with a JWT signature in this deployment (clients use client-x509 or client-secret),
        // and a key read from the header of the token being verified would be self-asserted. Fail closed.
        throw new VerificationException("Hybrid client JWT signatures are not accepted: no registered client key source is configured");
    }

    @Override
    public String getAlgorithm() {
        return algorithmId;
    }

    @Override
    public boolean isAsymmetricAlgorithm() {
        return true;
    }
}
