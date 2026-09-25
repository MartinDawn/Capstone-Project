package com.bk.research.pqc.provider;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCWellKnownProvider;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.keycloak.wellknown.WellKnownProvider;

public class HybridOIDCWellKnownProviderFactory extends OIDCWellKnownProviderFactory {

    @Override
    public WellKnownProvider create(KeycloakSession session) {
        return new HybridOIDCWellKnownProvider(session);
    }

    @Override
    public int getPriority() {
        // Higher priority than the default OIDCWellKnownProviderFactory (which is usually 0)
        return 10;
    }
}
