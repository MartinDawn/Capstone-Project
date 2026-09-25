package com.bk.research.pqc.keycloak;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.x509.AbstractClientCertificateFromHttpHeadersLookupFactory;
import org.keycloak.services.x509.X509ClientCertificateLookup;

public class PqcNginxProxySslClientCertificateLookupFactory extends AbstractClientCertificateFromHttpHeadersLookupFactory {

    public static final String PROVIDER_ID = "pqc-nginx";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public X509ClientCertificateLookup create(KeycloakSession session) {
        return new PqcNginxProxySslClientCertificateLookup(
                sslClientCertHttpHeader,
                sslChainHttpHeaderPrefix,
                certificateChainLength
        );
    }
}
