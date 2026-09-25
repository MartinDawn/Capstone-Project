package com.bk.research.classical.tpp;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.util.UUID;

@Service
public class CryptoService {

    private ECKey ecJwk;
    private KeyPair ecKeyPair;
    private String tppKeyId;

    @PostConstruct
    public void initKeys() throws Exception {
        tppKeyId = "tpp-key-" + UUID.randomUUID().toString().substring(0, 8);

        // Generate ECDSA KeyPair on NIST P-256 using Nimbus
        ecJwk = new ECKeyGenerator(Curve.P_256)
                .keyID(tppKeyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        ecKeyPair = ecJwk.toKeyPair();

        System.out.println("[TPP CryptoService] Classical ECDSA P-256 keypair generated. TPP Key ID: " + tppKeyId);
    }

    public ECKey getEcJwk() {
        return ecJwk;
    }

    public String getTppKeyId() {
        return tppKeyId;
    }

    public String getAlgorithm() {
        return "ES256";
    }

    public String sign(String payloadJson, String typ) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(typ))
                .keyID(tppKeyId)
                .build();
        Payload payload = new Payload(payloadJson);
        JWSObject jwsObject = new JWSObject(header, payload);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) ecKeyPair.getPrivate());
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public String signClassical(String payloadJson, String typ) throws Exception {
        return sign(payloadJson, typ);
    }

    public boolean verifySignature(String jwtStr, ECKey publicKey) {
        try {
            if (jwtStr == null || publicKey == null) return false;
            String jwtPart = jwtStr.split("~")[0];
            JWSObject jwsObject = JWSObject.parse(jwtPart);
            return jwsObject.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(publicKey.toECPublicKey()));
        } catch (Exception e) {
            return false;
        }
    }
}
