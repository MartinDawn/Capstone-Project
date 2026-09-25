package com.bk.research.classical.wallet;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.util.UUID;

@Service
public class CryptoService {

    private ECKey ecJwk;
    private KeyPair ecKeyPair;
    private String walletKeyId;

    @PostConstruct
    public void initKeys() throws Exception {
        Path keyPath = Path.of(System.getenv().getOrDefault(
                "SIGNING_KEY_STORE_PATH", "/app/state/wallet-signing-jwk.json"));
        if (Files.exists(keyPath)) {
            ecJwk = ECKey.parse(Files.readString(keyPath));
            walletKeyId = ecJwk.getKeyID();
            ecKeyPair = ecJwk.toKeyPair();
            System.out.println("[CryptoService] Loaded durable Wallet signing key. Wallet Key ID: " + walletKeyId);
            return;
        }
        initEphemeralKeys();

        Files.createDirectories(keyPath.getParent());
        Path temporaryPath = keyPath.resolveSibling(keyPath.getFileName() + ".tmp");
        Files.writeString(temporaryPath, ecJwk.toJSONString());
        try {
            Files.move(temporaryPath, keyPath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
            Files.move(temporaryPath, keyPath, StandardCopyOption.REPLACE_EXISTING);
        }

        System.out.println("[CryptoService] Classical ECDSA P-256 keypair generated. Wallet Key ID: " + walletKeyId);
    }

    public void initEphemeralKeys() throws Exception {
        walletKeyId = "wallet-key-" + UUID.randomUUID().toString().substring(0, 8);
        ecJwk = new ECKeyGenerator(Curve.P_256)
                .keyID(walletKeyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        ecKeyPair = ecJwk.toKeyPair();
    }

    public ECKey getEcJwk() {
        return ecJwk;
    }

    public String getAlgorithm() {
        return "ES256";
    }

    public String sign(String payloadJson, String typ) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(typ))
                .keyID(walletKeyId)
                .build();
        Payload payload = new Payload(payloadJson);
        JWSObject jwsObject = new JWSObject(header, payload);

        JWSSigner signer = new ECDSASigner((ECPrivateKey) ecKeyPair.getPrivate());
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    /**
     * Signs the OID4VCI proof-of-possession JWT. It is the only JWT that carries a public key in its header:
     * the issuer does not know the holder key yet, so the holder JWK travels in the standard `jwk` header.
     * Every other JWT is verified with a key the verifier already trusts.
     */
    public String signProof(String payloadJson, String typ) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(typ))
                .keyID(walletKeyId)
                .jwk(ecJwk.toPublicJWK())
                .build();
        JWSObject jwsObject = new JWSObject(header, new Payload(payloadJson));
        jwsObject.sign(new ECDSASigner((ECPrivateKey) ecKeyPair.getPrivate()));
        return jwsObject.serialize();
    }

    public String signClassical(String payloadJson, String typ) throws Exception {
        return sign(payloadJson, typ);
    }
}
