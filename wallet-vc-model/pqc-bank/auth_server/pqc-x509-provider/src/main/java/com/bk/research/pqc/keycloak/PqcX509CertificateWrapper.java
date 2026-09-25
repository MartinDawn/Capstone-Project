package com.bk.research.pqc.keycloak;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;
import javax.security.auth.x500.X500Principal;

public class PqcX509CertificateWrapper extends X509Certificate {

    private final X509Certificate delegate;

    public PqcX509CertificateWrapper(X509Certificate delegate) {
        this.delegate = delegate;
    }

    @Override
    public PublicKey getPublicKey() {
        PublicKey pk = null;
        try {
            pk = delegate.getPublicKey();
        } catch (Exception ignored) {}

        if (pk != null && pk.getAlgorithm() != null) {
            return pk;
        }

        return new PublicKey() {
            @Override
            public String getAlgorithm() {
                return "p384_mldsa65";
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }
        };
    }

    @Override
    public int getBasicConstraints() {
        return delegate.getBasicConstraints();
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        delegate.checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        delegate.checkValidity(date);
    }

    @Override
    public int getVersion() {
        return delegate.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {
        return delegate.getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        return delegate.getIssuerDN();
    }

    @Override
    public X500Principal getIssuerX500Principal() {
        return delegate.getIssuerX500Principal();
    }

    @Override
    public Principal getSubjectDN() {
        return delegate.getSubjectDN();
    }

    @Override
    public X500Principal getSubjectX500Principal() {
        return delegate.getSubjectX500Principal();
    }

    @Override
    public Date getNotBefore() {
        return delegate.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return delegate.getNotAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return delegate.getTBSCertificate();
    }

    @Override
    public byte[] getSignature() {
        return delegate.getSignature();
    }

    @Override
    public String getSigAlgName() {
        return delegate.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return delegate.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return delegate.getSigAlgParams();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return delegate.getIssuerUniqueID();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return delegate.getSubjectUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return delegate.getKeyUsage();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return delegate.getEncoded();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        delegate.verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        delegate.verify(key, sigProvider);
    }

    @Override
    public String toString() {
        return delegate.toString();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return delegate.hasUnsupportedCriticalExtension();
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return delegate.getCriticalExtensionOIDs();
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return delegate.getNonCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return delegate.getExtensionValue(oid);
    }
}
