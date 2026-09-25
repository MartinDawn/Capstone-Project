package com.bk.research.pqc.provider;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCWellKnownProvider;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

public class HybridOIDCWellKnownProvider extends OIDCWellKnownProvider {

    private final KeycloakSession session;

    public HybridOIDCWellKnownProvider(KeycloakSession session) {
        super(session, java.util.Collections.emptyMap(), false);
        this.session = session;
    }

    @Override
    public Object getConfig() {
        OIDCConfigurationRepresentation config = (OIDCConfigurationRepresentation) super.getConfig();
        
        // Override jwks_uri to point to our custom hybrid endpoint
        String realmName = session.getContext().getRealm().getName();
        String baseUrl = session.getContext().getUri().getBaseUri().toString();
        
        // Construct new URL: {baseUrl}/realms/{realmName}/hybrid-certs
        String hybridJwksUri = baseUrl + "realms/" + realmName + "/hybrid-certs";
        config.setJwksUri(hybridJwksUri);

        return config;
    }
}
