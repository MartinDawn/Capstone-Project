package com.bk.research.pqc.tpp;

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

    public ConformanceSigningController(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @PostMapping(value = "/api/test/sign-artifact", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> signArtifact(@RequestBody String bodyText) throws Exception {
        JSONObject body = new JSONObject(bodyText);
        JSONObject payload = body.getJSONObject("payload");
        String type = body.optString("typ", "JWT");
        String signedJwt = cryptoService.signHybrid(payload.toString(), type);
        return ResponseEntity.ok(new JSONObject()
            .put("signedJwt", signedJwt)
            .put("signerRole", "TPP")
            .put("signerKeyId", cryptoService.getEcJwk().getKeyID())
            .toString());
    }
}
