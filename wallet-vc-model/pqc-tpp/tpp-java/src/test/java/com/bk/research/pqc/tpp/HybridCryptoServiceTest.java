package com.bk.research.pqc.tpp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;

class HybridCryptoServiceTest {
    private static final int ML_DSA_65_SIGNATURE_BYTES = 3309;
    private CryptoService service;
    private String signingInput;
    private byte[] signature;
    private byte[] publicKey;

    @BeforeEach
    void setUp() throws Exception {
        service = new CryptoService();
        service.initKeys();
        String jwt = service.signHybrid("{\"sub\":\"tpp-1\"}", "JWT");
        String[] parts = jwt.split("\\.");
        signingInput = parts[0] + "." + parts[1];
        signature = Base64.getUrlDecoder().decode(parts[2]);
        publicKey = service.getCompositePublicKey().getEncoded();
        assertTrue(signature.length > ML_DSA_65_SIGNATURE_BYTES);
    }

    private boolean verify(String input, byte[] candidate, byte[] key) {
        return service.verifyHybridSignature(input, candidate, null, key, "MLDSA65");
    }

    @Test void hyF01ValidCompositeSignatureIsAccepted() { assertTrue(verify(signingInput, signature, publicKey)); }
    @Test void hyN01MissingClassicalComponentIsRejected() { assertFalse(verify(signingInput, Arrays.copyOf(signature, ML_DSA_65_SIGNATURE_BYTES), publicKey)); }
    @Test void hyN02MissingPqcComponentIsRejected() { assertFalse(verify(signingInput, Arrays.copyOfRange(signature, ML_DSA_65_SIGNATURE_BYTES, signature.length), publicKey)); }
    @Test void hyN03CorruptClassicalComponentIsRejected() { byte[] changed = signature.clone(); changed[changed.length - 1] ^= 0x01; assertFalse(verify(signingInput, changed, publicKey)); }
    @Test void hyN03CorruptPqcComponentIsRejected() { byte[] changed = signature.clone(); changed[0] ^= 0x01; assertFalse(verify(signingInput, changed, publicKey)); }
    @Test void hyN04ProtectedHeaderDowngradeIsRejected() throws Exception { JWSObject classicalOnly = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES384).type(JOSEObjectType.JWT).build(), new Payload("{\"sub\":\"tpp-1\"}")); classicalOnly.sign(new ECDSASigner(service.getEcJwk())); String[] compact = classicalOnly.serialize().split("\\."); assertFalse(verify(compact[0] + "." + compact[1], Base64.getUrlDecoder().decode(compact[2]), publicKey)); }
    @Test void hyN05DifferentRoleKeyIsRejected() throws Exception { CryptoService otherRole = new CryptoService(); otherRole.initKeys(); assertFalse(verify(signingInput, signature, otherRole.getCompositePublicKey().getEncoded())); }
}
