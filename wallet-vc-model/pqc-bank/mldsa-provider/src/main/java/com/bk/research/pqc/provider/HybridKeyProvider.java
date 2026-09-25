package com.bk.research.pqc.provider;

import com.bk.research.pqc.HybridKeyManager;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.KeyProvider;

import java.util.stream.Stream;

public class HybridKeyProvider implements KeyProvider {

    private final KeyWrapper keyWrapper;

    public HybridKeyProvider(String algorithmId) {
        this.keyWrapper = new KeyWrapper();
        this.keyWrapper.setKid("hybrid-" + algorithmId.toLowerCase() + "-kid");
        
        if (algorithmId.equals("ES256") || algorithmId.equals("ES384")) {
            this.keyWrapper.setType(KeyType.EC);
            this.keyWrapper.setCurve(algorithmId.equals("ES384") ? "P-384" : "P-256");
        } else if (algorithmId.equals("PS256") || algorithmId.equals("PS384")) {
            this.keyWrapper.setType(KeyType.RSA);
        } else {
            this.keyWrapper.setType(KeyType.EC);
            this.keyWrapper.setCurve("P-384");
        }
        
        this.keyWrapper.setAlgorithm(algorithmId);
        this.keyWrapper.setStatus(KeyStatus.ACTIVE);
        this.keyWrapper.setUse(KeyUse.SIG);
        
        // We only expose the classical public key via standard JWKS because Keycloak's core JWK classes
        // do not support ML-DSA keys yet. The client can either fetch the PQC key from our custom endpoint,
        // or for testing, assume they have it out-of-band.
        this.keyWrapper.setPrivateKey(HybridKeyManager.getInstance().getClassicalKeyPair(algorithmId).getPrivate());
        this.keyWrapper.setPublicKey(HybridKeyManager.getInstance().getClassicalKeyPair(algorithmId).getPublic());
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
        return Stream.of(keyWrapper);
    }

    @Override
    public void close() {}
}
