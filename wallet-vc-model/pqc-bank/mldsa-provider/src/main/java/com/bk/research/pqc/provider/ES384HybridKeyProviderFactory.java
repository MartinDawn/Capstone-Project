package com.bk.research.pqc.provider;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class ES384HybridKeyProviderFactory implements KeyProviderFactory {

    public static final String ID = "hybrid-es384-key";

    @Override
    public KeyProvider create(KeycloakSession session, ComponentModel model) {
        return new HybridKeyProvider("ES384");
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
    public String getHelpText() {
        return "Hybrid ES384 + p384_mldsa65 Key Provider";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }
}
