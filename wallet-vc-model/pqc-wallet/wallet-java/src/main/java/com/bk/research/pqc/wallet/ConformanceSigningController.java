package com.bk.research.pqc.wallet;

import org.json.JSONObject;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Test-only signer loaded exclusively by the conformance Spring profile. */
@Profile("conformance")
@RestController
public class ConformanceSigningController {
    private final CryptoService cryptoService;
    private final CryptoService replacementSigner;

    public ConformanceSigningController(CryptoService cryptoService) throws Exception {
        this.cryptoService = cryptoService;
        this.replacementSigner = new CryptoService();
        this.replacementSigner.initEphemeralKeys();
    }

    @PostMapping(value = "/api/test/sign-artifact", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> signArtifact(@RequestBody String bodyText) throws Exception {
        JSONObject body = new JSONObject(bodyText);
        JSONObject payload = body.getJSONObject("payload");
        String type = body.optString("typ", "JWT");
        boolean useReplacement = "replacement".equals(body.optString("signer_profile"));
        CryptoService signer = useReplacement ? replacementSigner : cryptoService;
        String signedJwt = signer.signHybrid(payload.toString(), type);
        return ResponseEntity.ok(new JSONObject()
            .put("signedJwt", signedJwt)
            .put("signerRole", "Wallet")
            .put("signerProfile", useReplacement ? "replacement" : "authorized")
            .put("signerKeyId", signer.getEcJwk().getKeyID())
            .put("signerPublicJwk", new JSONObject(signer.getEcJwk().toPublicJWK().toJSONString()))
            .put("signerCompositePublicKey", signer.getCompositePublicKeyBase64())
            .toString());
    }
}
