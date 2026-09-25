package com.bk.research.pqc.keycloak;

import org.keycloak.common.util.PemException;
import org.keycloak.services.x509.AbstractClientCertificateFromHttpHeadersLookup;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class PqcNginxProxySslClientCertificateLookup extends AbstractClientCertificateFromHttpHeadersLookup {

    public PqcNginxProxySslClientCertificateLookup(String sslClientCertHttpHeader, String sslCertChainHttpHeaderPrefix, int certificateChainLength) {
        super(sslClientCertHttpHeader, sslCertChainHttpHeaderPrefix, certificateChainLength);
    }

    @Override
    protected X509Certificate decodeCertificateFromPem(String pem) throws PemException {
        if (pem == null || pem.trim().isEmpty()) {
            return null;
        }
        try {
            pem = java.net.URLDecoder.decode(pem, "UTF-8");
        } catch (UnsupportedEncodingException ignored) {
        }

        if (!pem.contains("-----BEGIN CERTIFICATE-----")) {
            pem = "-----BEGIN CERTIFICATE-----\n" + pem + "\n-----END CERTIFICATE-----";
        }

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8));
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
            if (cert == null) {
                return null;
            }
            return new PqcX509CertificateWrapper(cert);
        } catch (Exception e) {
            throw new PemException(e);
        }
    }
}
