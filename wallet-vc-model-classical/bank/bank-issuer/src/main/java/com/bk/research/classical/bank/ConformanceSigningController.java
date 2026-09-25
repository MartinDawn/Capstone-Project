package com.bk.research.classical.bank;

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
    private final CertificateRecordStore certificateRecordStore;

    public ConformanceSigningController(CryptoService cryptoService, CertificateRecordStore certificateRecordStore) {
        this.cryptoService = cryptoService;
        this.certificateRecordStore = certificateRecordStore;
    }

    @PostMapping(value = "/api/test/sign-artifact", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> signArtifact(@RequestBody String bodyText) throws Exception {
        JSONObject body = new JSONObject(bodyText);
        JSONObject payload = body.getJSONObject("payload");
        String type = body.optString("typ", "JWT");
        String signedJwt = cryptoService.sign(payload.toString(), type);
        // Re-committing the issuance record is an explicit, opt-in fixture step. It keeps the issuance-binding
        // layer valid so a case can reach a later predicate; without it the credential stays bound to the
        // component digest committed at F1, so the record-versus-credential check below stays testable.
        boolean rebind = body.optBoolean("rebind_issuance_record", false);
        if (rebind && payload.has("holder_cert_ref")) {
            String certRef = payload.getString("holder_cert_ref");
            certificateRecordStore.updateCredentialComponentDigest(certRef, certificateRecordStore.computeThumbprint(signedJwt));
        }
        return ResponseEntity.ok(new JSONObject()
            .put("signedJwt", signedJwt)
            .put("signerRole", "BankIssuer")
            .put("signerKeyId", cryptoService.getEcJwk().getKeyID())
            .toString());
    }
}
