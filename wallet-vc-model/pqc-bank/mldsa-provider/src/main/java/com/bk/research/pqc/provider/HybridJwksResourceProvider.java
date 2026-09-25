package com.bk.research.pqc.provider;

import com.bk.research.pqc.HybridKeyManager;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class HybridJwksResourceProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(HybridJwksResourceProvider.class.getName());
    private final KeycloakSession session;

    public HybridJwksResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public JSONWebKeySet getJwks() {
        org.keycloak.jose.jwk.JWKBuilder builder = org.keycloak.jose.jwk.JWKBuilder.create();
        JSONWebKeySet keySet = new JSONWebKeySet();
        
        session.keys().getKeysStream(session.getContext().getRealm()).forEach(keyWrapper -> {
            try {
                JWK jwk = null;
                if (keyWrapper.getPublicKey() != null) {
                    if (keyWrapper.getAlgorithmOrDefault().startsWith("ES")) {
                        jwk = builder.kid(keyWrapper.getKid()).algorithm(keyWrapper.getAlgorithmOrDefault()).ec(keyWrapper.getPublicKey(), keyWrapper.getUse());
                    } else if (keyWrapper.getAlgorithmOrDefault().startsWith("RS") || keyWrapper.getAlgorithmOrDefault().startsWith("PS")) {
                        jwk = builder.kid(keyWrapper.getKid()).algorithm(keyWrapper.getAlgorithmOrDefault()).rsa(keyWrapper.getPublicKey(), keyWrapper.getUse());
                    }
                }
                
                if (jwk != null) {
                    if (keyWrapper.getKid() != null && keyWrapper.getKid().startsWith("hybrid-")) {
                        Map<String, Object> otherClaims = jwk.getOtherClaims();
                        if (otherClaims == null) {
                            otherClaims = new HashMap<>();
                        }
                        
                        String compositePubB64 = HybridKeyManager.getInstance().getCompositePublicKeyBase64();
                        Map<String, String> pqcKeys = new HashMap<>();
                        pqcKeys.put("p384_mldsa65", compositePubB64);
                        pqcKeys.put("MLDSA65", compositePubB64);
                        pqcKeys.put("MLDSA65-ECDSA-P384-SHA512", compositePubB64);
                        
                        otherClaims.put("pqc_keys", pqcKeys);
                        otherClaims.put("composite_pub", compositePubB64);
                        otherClaims.put("composite_alg", HybridKeyManager.COMPOSITE_ALG);
                        jwk.setOtherClaims("composite_pub", compositePubB64);
                        jwk.setOtherClaims("composite_alg", HybridKeyManager.COMPOSITE_ALG);
                        jwk.setOtherClaims("pqc_keys", pqcKeys);
                    }
                    
                    if (keySet.getKeys() == null) {
                        keySet.setKeys(new JWK[]{jwk});
                    } else {
                        JWK[] currentKeys = keySet.getKeys();
                        JWK[] newKeys = new JWK[currentKeys.length + 1];
                        System.arraycopy(currentKeys, 0, newKeys, 0, currentKeys.length);
                        newKeys[currentKeys.length] = jwk;
                        keySet.setKeys(newKeys);
                    }
                }
            } catch (Exception e) {
                logger.severe("Failed to build JWK for key: " + keyWrapper.getKid() + ". " + e.getMessage());
            }
        });

        return keySet;
    }

    @Override
    public void close() {
    }
}
