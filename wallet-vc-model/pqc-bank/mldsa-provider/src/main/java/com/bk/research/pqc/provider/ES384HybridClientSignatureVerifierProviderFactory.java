package com.bk.research.pqc.provider;

import org.keycloak.Config;
import org.keycloak.crypto.ClientSignatureVerifierProvider;
import org.keycloak.crypto.ClientSignatureVerifierProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class ES384HybridClientSignatureVerifierProviderFactory implements ClientSignatureVerifierProviderFactory {

    public static final String ID = "ES384";

    @Override
    public ClientSignatureVerifierProvider create(KeycloakSession session) {
        return new HybridClientSignatureVerifierProvider(session, ID);
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int order() {
        return 100;
    }
}
