package com.bk.research.pqc.provider;

import org.keycloak.Config;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class EdDSAHybridSignatureProviderFactory implements SignatureProviderFactory {

    public static final String ID = "EdDSA";

    @Override
    public SignatureProvider create(KeycloakSession session) {
        return new HybridSignatureProvider(session, ID);
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
