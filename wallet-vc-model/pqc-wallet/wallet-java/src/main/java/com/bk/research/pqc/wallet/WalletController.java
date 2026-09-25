package com.bk.research.pqc.wallet;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@CrossOrigin(origins = "*")
public class WalletController {

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private PqcRestTemplate pqcRestTemplate;

    @Value("${WALLET_PORT:5000}")
    private String port;

    @Value("${BANK_ISSUER_URL:http://oqs-wallet-outbound:18443}")
    private String bankIssuerUrl;

    @Value("${KEYCLOAK_URL:http://oqs-wallet-outbound:18443}")
    private String keycloakUrl;

    @Value("${FRONTEND_BANK_ISSUER_URL:http://localhost:7000}")
    private String frontendBankIssuerUrl;

    @Value("${FRONTEND_KEYCLOAK_URL:http://localhost:8080}")
    private String frontendKeycloakUrl;

    @Value("${CLIENT_ID:fapi-test-client}")
    private String clientId;

    @Value("${REDIRECT_URI:http://localhost:5000/callback}")
    private String redirectUri;

    @Value("${TPP_URL:http://wallet-gateway:16443}")
    private String tppUrl;

    // ── In-memory state ──────────────────────────────────────
    private final Map<String, JSONObject> vcs = new ConcurrentHashMap<>();
    private final Map<String, JSONObject> sessions = new ConcurrentHashMap<>();
    private final Map<String, JSONObject> pendingDelegateRequests = new ConcurrentHashMap<>();
    private final List<JSONObject> protocolLog = new ArrayList<>();
    private volatile boolean userClearedVcs = false;

    // ── Logging ───────────────────────────────────────────────
    private void logProtocol(String step, String direction, String desc, JSONObject data) {
        JSONObject log = new JSONObject();
        log.put("id", UUID.randomUUID().toString());
        log.put("timestamp", new Date().toString());
        log.put("step", step);
        log.put("direction", direction);
        log.put("description", desc);
        log.put("data", data != null ? data : new JSONObject());
        synchronized (protocolLog) {
            protocolLog.add(0, log);
            if (protocolLog.size() > 300) protocolLog.remove(protocolLog.size() - 1);
        }
        System.out.println("[Wallet][" + step + "] " + desc);
    }

    private String getDirectKcBase() {
        return keycloakUrl + "/realms/fapi-demo/protocol/openid-connect";
    }

    private String generateClientAssertion() throws Exception {
        JSONObject payload = new JSONObject();
        payload.put("iss", clientId);
        payload.put("sub", clientId);
        payload.put("aud", frontendKeycloakUrl + "/realms/fapi-demo");
        payload.put("iat", System.currentTimeMillis() / 1000 - 30);
        payload.put("exp", System.currentTimeMillis() / 1000 + 300);
        payload.put("jti", UUID.randomUUID().toString());
        return cryptoService.signHybrid(payload.toString(), "JWT");
    }

    // ── Config ────────────────────────────────────────────────
    @GetMapping(value = "/api/config", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getConfig() {
        JSONObject res = new JSONObject();
        res.put("bankIssuerUrl", frontendBankIssuerUrl);
        res.put("keycloakUrl", frontendKeycloakUrl);
        res.put("realm", "fapi-demo");
        res.put("redirectUri", redirectUri);
        res.put("tppUrl", tppUrl);
        return res.toString();
    }

    @GetMapping(value = "/api/wallet-key", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getWalletKey() {
        JSONObject res = new JSONObject();
        JSONObject jwk = new JSONObject(cryptoService.getEcJwk().toPublicJWK().toJSONString());
        jwk.put("composite_pub", cryptoService.getCompositePublicKeyBase64());
        jwk.put("alg", "MLDSA65-ECDSA-P384-SHA512");
        res.put("jwk", jwk);
        res.put("kid", cryptoService.getEcJwk().getKeyID());
        res.put("composite_pub", cryptoService.getCompositePublicKeyBase64());
        res.put("pqcAlg", "MLDSA65");
        return res.toString();
    }

    @GetMapping(value = "/api/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getJwks() {
        JSONObject res = new JSONObject();
        JSONObject jwk = new JSONObject(cryptoService.getEcJwk().toPublicJWK().toJSONString());
        jwk.put("composite_pub", cryptoService.getCompositePublicKeyBase64());
        jwk.put("alg", "MLDSA65-ECDSA-P384-SHA512");
        res.put("keys", new JSONArray().put(jwk));
        return res.toString();
    }

    @GetMapping(value = "/api/fetch-offer", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> fetchOffer(@RequestParam(name = "type", defaultValue = "identity") String type) {
        try {
            String offerUrl = bankIssuerUrl + "/offer/" + type;
            logProtocol("Fetching Credential Offer", "outgoing",
                "Fetching Credential Offer from Bank Issuer via PQC mTLS: " + offerUrl, null);

            ResponseEntity<String> offerRes = pqcRestTemplate.getRestTemplate()
                .getForEntity(offerUrl, String.class);

            return ResponseEntity.status(offerRes.getStatusCode()).body(offerRes.getBody());
        } catch (Exception e) {
            System.err.println("[Wallet] Error fetching offer from bank: " + e.getMessage());
            JSONObject err = new JSONObject();
            err.put("error", "fetch_offer_failed");
            err.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(err.toString());
        }
    }

    // ── OID4VCI Step 1: Receive Offer ─────────────────────────
    /**
     * Receive Credential Offer from Bank.
     * - If offerUri exists (openid-credential-offer://...): parse JSON from query param
     * - If offer JSON exists in body: use directly
     * - If nothing: actually call bank-issuer GET /offer/{type}
     * Then fetch issuer metadata from /.well-known/openid-credential-issuer
     */
    @PostMapping("/api/receive-offer")
    public String receiveOffer(@RequestBody String bodyStr) throws Exception {
        JSONObject body = new JSONObject(bodyStr);

        JSONObject offer;
        String credConfig;

        String offerUri = body.optString("offerUri", "").trim();
        String credentialConfigId = body.optString("credentialConfigId", "AuthorizationCredential");

        if (!offerUri.isEmpty()) {
            // Parse openid-credential-offer:// URI
            String encodedOffer = offerUri.replaceFirst("openid-credential-offer://\\?credential_offer=", "");
            String decoded = URLDecoder.decode(encodedOffer, StandardCharsets.UTF_8);
            offer = new JSONObject(decoded);
            credConfig = offer.optJSONArray("credential_configuration_ids") != null
                ? offer.getJSONArray("credential_configuration_ids").getString(0)
                : credentialConfigId;
            logProtocol("Credential Offer Parsed", "incoming",
                "Parsed Credential Offer from URI for " + credConfig, offer);
        } else if (body.has("offer")) {
            offer = body.getJSONObject("offer");
            credConfig = offer.optJSONArray("credential_configuration_ids") != null
                ? offer.getJSONArray("credential_configuration_ids").getString(0)
                : credentialConfigId;
        } else {
            // Fetch offer from bank-issuer via PQC proxy
            String type = "authorization";
            String offerUrl = bankIssuerUrl + "/offer/" + type;
            logProtocol("Fetching Credential Offer", "outgoing",
                "Fetching Credential Offer from Bank Issuer: " + offerUrl, null);

            ResponseEntity<String> offerRes = pqcRestTemplate.getRestTemplate()
                .getForEntity(offerUrl, String.class);

            JSONObject offerData = new JSONObject(offerRes.getBody());
            offer = offerData.getJSONObject("offer");
            credConfig = offerData.optString("credentialConfigId", credentialConfigId);
            logProtocol("Credential Offer Received", "incoming",
                "Received Credential Offer from Bank for " + credConfig, offer);
        }

        String issuerState = "";
        if (offer.has("grants")) {
            JSONObject grants = offer.optJSONObject("grants");
            if (grants != null && grants.has("authorization_code")) {
                issuerState = grants.getJSONObject("authorization_code").optString("issuer_state", "");
            }
        }

        // Fetch issuer metadata
        JSONObject metadata = new JSONObject();
        try {
            String metadataUrl = bankIssuerUrl + "/.well-known/openid-credential-issuer";
            logProtocol("Fetching Issuer Metadata", "outgoing",
                "Fetching OID4VCI metadata from " + metadataUrl, null);
            ResponseEntity<String> metaRes = pqcRestTemplate.getRestTemplate()
                .getForEntity(metadataUrl, String.class);
            metadata = new JSONObject(metaRes.getBody());
            logProtocol("Issuer Metadata Received", "incoming",
                "Metadata fetched successfully", new JSONObject().put("credential_endpoint",
                    metadata.optString("credential_endpoint")));
        } catch (Exception e) {
            System.err.println("[Wallet] Could not fetch issuer metadata: " + e.getMessage());
        }

        String sessionId = UUID.randomUUID().toString();
        JSONObject session = new JSONObject();
        session.put("id", sessionId);
        session.put("credConfig", credConfig);
        session.put("state", UUID.randomUUID().toString());
        session.put("nonce", UUID.randomUUID().toString());
        session.put("issuerState", issuerState);
        session.put("offer", offer);
        session.put("metadata", metadata);
        sessions.put(sessionId, session);

        JSONObject res = new JSONObject();
        res.put("sessionId", sessionId);
        res.put("credConfig", credConfig);
        res.put("offer", offer);
        res.put("metadata", new JSONObject().put("credential_endpoint",
            metadata.optString("credential_endpoint", bankIssuerUrl + "/credential")));
        return res.toString();
    }

    // ── OID4VCI Step 2: Start Auth ────────────────────────────
    @PostMapping("/api/start-auth")
    public String startAuth(@RequestBody String bodyStr) throws Exception {
        JSONObject body = new JSONObject(bodyStr);
        String sessionId = body.getString("sessionId");
        JSONObject session = sessions.get(sessionId);
        if (session == null) {
            return new JSONObject().put("error", "Session not found").toString();
        }

        String scope = "openid profile email authorization_credential accounts:read transfers:read transfers:write profile:read";

        // PKCE
        String codeVerifier = UUID.randomUUID().toString().replace("-", "") +
            UUID.randomUUID().toString().replace("-", "");
        session.put("codeVerifier", codeVerifier);

        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-384");
        byte[] digest = md.digest(codeVerifier.getBytes());
        String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        session.put("codeChallenge", codeChallenge);

        // PAR request
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        URI fKcUri = URI.create(frontendKeycloakUrl);
        String fKcHost = fKcUri.getHost() + (fKcUri.getPort() != -1 && fKcUri.getPort() != 80 && fKcUri.getPort() != 443 ? ":" + fKcUri.getPort() : "");
        headers.set("X-Forwarded-Host", fKcHost);
        headers.set("X-Forwarded-Proto", fKcUri.getScheme() != null ? fKcUri.getScheme() : "http");

        MultiValueMap<String, String> parBody = new LinkedMultiValueMap<>();
        parBody.add("client_id", clientId);
        parBody.add("response_type", "code");
        parBody.add("redirect_uri", redirectUri);
        parBody.add("scope", scope);
        parBody.add("state", session.getString("state"));
        parBody.add("nonce", session.getString("nonce"));
        parBody.add("code_challenge", codeChallenge);
        parBody.add("code_challenge_method", "S384");
        if (!session.optString("issuerState", "").isEmpty()) {
            parBody.add("issuer_state", session.getString("issuerState"));
        }

        String authUrl;
        try {
            logProtocol("PAR Request", "outgoing", "Pushing Authorization Request to Keycloak", null);
            ResponseEntity<String> parRes = pqcRestTemplate.getRestTemplate().postForEntity(
                getDirectKcBase() + "/ext/par/request", new HttpEntity<>(parBody, headers), String.class);
            JSONObject parData = new JSONObject(parRes.getBody());
            String requestUri = parData.getString("request_uri");
            logProtocol("PAR Response", "incoming", "PAR successful", parData);
            authUrl = frontendKeycloakUrl + "/realms/fapi-demo/protocol/openid-connect/auth" +
                "?client_id=" + clientId +
                "&request_uri=" + requestUri;
        } catch (Exception e) {
            System.err.println("[Wallet] PAR failed: " + e.getMessage());
            // Fallback direct auth URL
            authUrl = frontendKeycloakUrl + "/realms/fapi-demo/protocol/openid-connect/auth" +
                "?client_id=" + clientId +
                "&response_type=code" +
                "&redirect_uri=" + redirectUri +
                "&scope=" + scope.replace(" ", "%20") +
                "&state=" + session.getString("state") +
                "&nonce=" + session.getString("nonce") +
                "&code_challenge=" + codeChallenge +
                "&code_challenge_method=S384";
        }

        logProtocol("Auth Redirect", "outgoing", "Redirecting user to Keycloak", null);

        JSONObject res = new JSONObject();
        res.put("sessionId", sessionId);
        res.put("authUrl", authUrl);
        return res.toString();
    }

    // ── OID4VCI Step 3: Callback ──────────────────────────────
    @GetMapping("/callback")
    public RedirectView callback(@RequestParam String code, @RequestParam String state) throws Exception {
        JSONObject session = null;
        for (JSONObject s : sessions.values()) {
            if (s.getString("state").equals(state)) {
                session = s;
                break;
            }
        }
        if (session == null) return new RedirectView("/?error=state_mismatch");

        // Exchange code → token
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("X-Forwarded-Host", "localhost:8080");
        headers.set("X-Forwarded-Proto", "http");

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "authorization_code");
        map.add("code", code);
        map.add("redirect_uri", redirectUri);
        map.add("client_id", clientId);
        if (session.has("codeVerifier")) {
            map.add("code_verifier", session.getString("codeVerifier"));
        }

        logProtocol("Token Exchange", "outgoing", "Exchanging code for token via PQC mTLS", null);

        JSONObject tokenData;
        try {
            ResponseEntity<String> response = pqcRestTemplate.getRestTemplate().postForEntity(
                getDirectKcBase() + "/token", new HttpEntity<>(map, headers), String.class);
            tokenData = new JSONObject(response.getBody());
        } catch (org.springframework.web.client.HttpStatusCodeException e) {
            System.err.println("[Wallet] Token exchange failed: " + e.getResponseBodyAsString());
            logProtocol("Token Error", "incoming", "Token exchange failed: " + e.getResponseBodyAsString(), null);
            return new RedirectView("/?error=code_invalid_or_expired");
        }

        if (!tokenData.has("access_token")) {
            logProtocol("Token Error", "incoming", "Token exchange failed", tokenData);
            return new RedirectView("/?error=token_error");
        }

        String accessToken = tokenData.getString("access_token");
        String cNonce = tokenData.optString("c_nonce", UUID.randomUUID().toString());
        session.put("accessToken", accessToken);
        session.put("cNonce", cNonce);
        logProtocol("Token Received", "incoming", "Access token received from Keycloak",
            new JSONObject().put("scope", tokenData.optString("scope")));

        // Request Credential
        JSONObject proofPayload = new JSONObject();
        proofPayload.put("iss", clientId);
        proofPayload.put("aud", frontendBankIssuerUrl != null && !frontendBankIssuerUrl.isEmpty() ? frontendBankIssuerUrl : bankIssuerUrl);
        proofPayload.put("iat", System.currentTimeMillis() / 1000);
        proofPayload.put("nonce", cNonce);
        proofPayload.put("jti", UUID.randomUUID().toString());

        String proofJwt = cryptoService.signProofHybrid(proofPayload.toString(), "openid4vci-proof+jwt");

        JSONObject credReq = new JSONObject();
        credReq.put("format", "vc+sd-jwt");
        credReq.put("credential_configuration_id", session.getString("credConfig"));
        JSONObject proof = new JSONObject();
        proof.put("proof_type", "jwt");
        proof.put("jwt", proofJwt);
        credReq.put("proof", proof);

        HttpHeaders credHeaders = new HttpHeaders();
        credHeaders.setContentType(MediaType.APPLICATION_JSON);
        credHeaders.setBearerAuth(accessToken);
        credHeaders.set("X-Forwarded-Host", "localhost:7000");

        logProtocol("Credential Request", "outgoing", "Requesting VC via PQC mTLS", null);

        ResponseEntity<String> credRes = pqcRestTemplate.getRestTemplate().postForEntity(
            bankIssuerUrl + "/credential", new HttpEntity<>(credReq.toString(), credHeaders), String.class);

        JSONObject credData = new JSONObject(credRes.getBody());
        String sdJwt = credData.getString("credential");

        String jti = UUID.randomUUID().toString();
        JSONObject vc = new JSONObject();
        vc.put("jti", jti);
        vc.put("type", session.getString("credConfig"));
        vc.put("sdJwt", sdJwt);
        vc.put("receivedAt", new Date().toString());

        // Parse payload for UI display
        String[] parts = sdJwt.split("\\.");
        if (parts.length > 1) {
            try {
                JSONObject payload = new JSONObject(new String(Base64.getDecoder().decode(parts[1])));
                vc.put("payload", payload);
                vc.put("jti", payload.optString("jti", jti));
                jti = vc.getString("jti");
            } catch (Exception e) {
                System.err.println("[Wallet] Could not parse VC payload: " + e.getMessage());
            }
        }

        // Parse SD-JWT disclosures
        JSONObject disclosedClaims = parseDisclosures(sdJwt);
        vc.put("disclosedClaims", disclosedClaims);

        vcs.put(jti, vc);
        userClearedVcs = false;
        logProtocol("Credential Received", "incoming",
            "VC stored in wallet: " + session.getString("credConfig"),
            new JSONObject().put("jti", jti).put("type", session.getString("credConfig")));

        return new RedirectView("/?session=" + session.getString("id") + "&success=true");
    }

    // ── List VCs ──────────────────────────────────────────────
    @GetMapping("/api/vcs")
    public String getVcs() {
        if (vcs.isEmpty() && !userClearedVcs) {
            ensureAuthorizationVc();
        }
        JSONObject res = new JSONObject();
        res.put("vcs", vcs.values());
        res.put("count", vcs.size());
        return res.toString();
    }

    // ── Delete VC ──────────────────────────────────────────────
    @DeleteMapping("/api/vcs/{jti}")
    public ResponseEntity<String> deleteVcById(@PathVariable("jti") String jti) {
        return deleteVcInternal(jti);
    }

    @PostMapping("/api/delete-vc")
    public ResponseEntity<String> deleteVc(@RequestBody(required = false) String bodyStr) {
        String jti = "";
        if (bodyStr != null && !bodyStr.trim().isEmpty()) {
            try {
                JSONObject body = new JSONObject(bodyStr);
                jti = body.optString("jti", "");
            } catch (Exception ignored) {}
        }
        return deleteVcInternal(jti);
    }

    private ResponseEntity<String> deleteVcInternal(String jti) {
        userClearedVcs = true;
        if (jti == null || jti.trim().isEmpty()) {
            vcs.clear();
            logProtocol("All VCs Cleared", "internal", "Cleared all credentials from wallet", null);
            return ResponseEntity.ok(new JSONObject().put("success", true).put("clearedAll", true).toString());
        }
        JSONObject removed = vcs.remove(jti);
        if (removed != null) {
            logProtocol("VC Deleted", "internal", "Deleted VC from wallet: " + jti,
                new JSONObject().put("jti", jti).put("type", removed.optString("type")));
            return ResponseEntity.ok(new JSONObject().put("success", true).put("deletedJti", jti).toString());
        }
        return ResponseEntity.status(404).body(new JSONObject().put("error", "VC not found: " + jti).toString());
    }

    public synchronized String ensureAuthorizationVc() {
        for (JSONObject vc : vcs.values()) {
            if ("AuthorizationCredential".equals(vc.optString("type", ""))) {
                return vc.optString("jti", "");
            }
        }
        try {
            logProtocol("Auto-Provisioning Authorization Credential", "outgoing",
                "Requesting initial Scope VC from Bank Issuer via PQC mTLS", null);

            long now = System.currentTimeMillis() / 1000;


            JSONObject proofPayload = new JSONObject();
            proofPayload.put("iss", clientId);
            proofPayload.put("aud", frontendBankIssuerUrl != null && !frontendBankIssuerUrl.isEmpty() ? frontendBankIssuerUrl : bankIssuerUrl);
            proofPayload.put("iat", now);
            proofPayload.put("nonce", UUID.randomUUID().toString());
            proofPayload.put("jti", UUID.randomUUID().toString());

            String proofJwt = cryptoService.signProofHybrid(proofPayload.toString(), "openid4vci-proof+jwt");

            JSONObject credReq = new JSONObject();
            credReq.put("format", "vc+sd-jwt");
            credReq.put("credential_configuration_id", "AuthorizationCredential");
            JSONObject proof = new JSONObject();
            proof.put("proof_type", "jwt");
            proof.put("jwt", proofJwt);
            credReq.put("proof", proof);

            HttpHeaders credHeaders = new HttpHeaders();
            credHeaders.setContentType(MediaType.APPLICATION_JSON);
            credHeaders.set("X-Forwarded-Host", "localhost:7000");

            ResponseEntity<String> credRes = pqcRestTemplate.getRestTemplate().postForEntity(
                bankIssuerUrl + "/api/internal/bootstrap-credential", new HttpEntity<>(credReq.toString(), credHeaders), String.class);

            if (credRes.getStatusCode().is2xxSuccessful()) {
                JSONObject credData = new JSONObject(credRes.getBody());
                String sdJwt = credData.getString("credential");

                String jti = UUID.randomUUID().toString();
                JSONObject vc = new JSONObject();
                vc.put("jti", jti);
                vc.put("type", "AuthorizationCredential");
                vc.put("sdJwt", sdJwt);
                vc.put("receivedAt", new Date().toString());

                String[] parts = sdJwt.split("\\.");
                if (parts.length > 1) {
                    try {
                        JSONObject payload = new JSONObject(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
                        vc.put("payload", payload);
                        vc.put("jti", payload.optString("jti", jti));
                        jti = vc.getString("jti");
                    } catch (Exception ignored) {}
                }

                JSONObject disclosedClaims = parseDisclosures(sdJwt);
                vc.put("disclosedClaims", disclosedClaims);

                vcs.put(jti, vc);
                logProtocol("Scope VC Auto-Provisioned", "incoming",
                    "Stored Bank-signed Root Authorization VC (Hybrid ML-DSA): " + jti, vc);
                return jti;
            }
        } catch (Exception e) {
            System.err.println("[Wallet] Auto-provision Authorization VC failed: " + e.getMessage());
        }
        return "";
    }

    @PostMapping(value = "/api/provision-scope-vc", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> provisionScopeVc() {
        userClearedVcs = false;
        vcs.entrySet().removeIf(e -> "AuthorizationCredential".equals(e.getValue().optString("type", "")));
        String jti = ensureAuthorizationVc();
        if (jti != null && !jti.isEmpty()) {
            JSONObject vc = vcs.get(jti);
            return ResponseEntity.ok(new JSONObject()
                .put("success", true)
                .put("jti", jti)
                .put("credential", vc != null ? vc.optString("sdJwt", "") : "")
                .toString());
        }
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new JSONObject().put("error", "Failed to provision Scope VC").toString());
    }

    // ── Create Delegate (manual / legacy) ────────────────────
    @PostMapping("/api/create-delegate")
    public String createDelegate(@RequestBody String bodyStr) throws Exception {
        JSONObject body = new JSONObject(bodyStr);
        String authzVcJti = body.getString("authzVcJti");
        String tppClientId = body.getString("tppClientId");
        JSONObject tppPublicKey = body.optJSONObject("tppPublicKey");

        // Get selected scopes, fall back to all scopes from the authz VC
        List<String> selectedScopes = new ArrayList<>();
        if (body.has("selectedScopes")) {
            body.getJSONArray("selectedScopes").forEach(s -> selectedScopes.add(s.toString()));
        }

        // Validate against authorization VC scopes
        JSONObject authzVc = vcs.get(authzVcJti);
        if (authzVc == null) {
            return new JSONObject().put("error", "Authorization VC not found: " + authzVcJti).toString();
        }

        JSONObject disclosedClaims = authzVc.optJSONObject("disclosedClaims");
        List<String> authzScopes = new ArrayList<>();
        if (disclosedClaims != null && disclosedClaims.has("scopes")) {
            disclosedClaims.getJSONArray("scopes").forEach(s -> authzScopes.add(s.toString()));
        }

        List<String> validScopes = selectedScopes.isEmpty() ? authzScopes :
            selectedScopes.stream().filter(authzScopes::contains).collect(java.util.stream.Collectors.toList());

        return buildAndStoreDelegateVc(authzVcJti, tppClientId, tppPublicKey, validScopes);
    }

    // ── Delegate Request Flow (TPP-initiated) ─────────────────

    /**
     * TPP sends Delegate VC request to Wallet.
     * Body: { tppClientId, requestedScopes: [...], tppPublicJwk: {...}, walletUrl (optional) }
     * Response: { requestId, status: "PENDING" }
     */
    @PostMapping("/api/delegate-request")
    public ResponseEntity<String> receiveDelegateRequest(@RequestBody String bodyStr) {
        try {
            JSONObject body = new JSONObject(bodyStr);
            String tppClientId = body.optString("tppClientId", "");
            JSONArray requestedScopes = body.optJSONArray("requestedScopes");
            JSONObject tppPublicJwk = body.optJSONObject("tppPublicJwk");

            boolean hasScopes = requestedScopes != null && !requestedScopes.isEmpty();

            if (tppClientId.isEmpty() || !hasScopes) {
                return ResponseEntity.badRequest()
                    .body(new JSONObject().put("error", "Missing tppClientId or requested scopes").toString());
            }

            String requestId = body.optString("requestId", UUID.randomUUID().toString());
            JSONObject request = new JSONObject();
            request.put("requestId", requestId);
            request.put("tppClientId", tppClientId);
            request.put("requestedScopes", requestedScopes != null ? requestedScopes : new JSONArray());
            if (tppPublicJwk != null) request.put("tppPublicJwk", tppPublicJwk);
            if (body.has("ch_das")) request.put("ch_das", body.getString("ch_das"));
            if (body.has("challenge")) request.put("challenge", body.getJSONObject("challenge"));
            if (body.has("tpp_redirect_uri")) request.put("tpp_redirect_uri", body.getString("tpp_redirect_uri"));
            if (body.has("redirect_uri")) request.put("tpp_redirect_uri", body.getString("redirect_uri"));
            request.put("status", "PENDING");
            request.put("createdAt", new Date().toString());

            pendingDelegateRequests.put(requestId, request);

            logProtocol("Delegate Request Received", "incoming",
                "TPP '" + tppClientId + "' requests Open Banking delegation",
                request);

            JSONObject res = new JSONObject();
            res.put("requestId", requestId);
            res.put("status", "PENDING");
            return ResponseEntity.ok(res.toString());
        } catch (Exception e) {
            return ResponseEntity.status(500)
                .body(new JSONObject().put("error", e.getMessage()).toString());
        }
    }

    /**
     * OID4VP Endpoint: Wallet fetches delegation request from TPP and stores locally in pendingDelegateRequests.
     */
    @GetMapping(value = "/api/fetch-tpp-request", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> fetchTppRequest(
            @RequestParam(name = "tppUrl", required = false) String targetTppUrl,
            @RequestParam("requestId") String reqId) {
        try {
            String cleanTppUrl = (tppUrl != null && !tppUrl.trim().isEmpty()) ? tppUrl.trim() : targetTppUrl;
            if (cleanTppUrl.contains("localhost") || cleanTppUrl.contains("127.0.0.1")) {
                cleanTppUrl = cleanTppUrl.replaceAll("localhost|127\\.0\\.0\\.1", "host.docker.internal");
            }
            String fetchUrl = cleanTppUrl + "/api/public/delegate-request/" + reqId;
            logProtocol("Fetching TPP Request (OID4VP)", "outgoing", "Fetching request details from " + fetchUrl, null);

            ResponseEntity<String> tppRes = pqcRestTemplate.getRestTemplate().getForEntity(fetchUrl, String.class);
            JSONObject reqData = new JSONObject(tppRes.getBody());
            reqData.put("tppUrl", cleanTppUrl);
            reqData.put("requestId", reqId);
            if (!reqData.has("status")) reqData.put("status", "PENDING");

            pendingDelegateRequests.put(reqId, reqData);
            logProtocol("TPP Request Imported", "incoming", "Successfully imported request " + reqId + " from TPP", reqData);

            JSONObject res = new JSONObject();
            res.put("success", true);
            res.put("request", reqData);
            return ResponseEntity.ok(res.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(new JSONObject().put("error", "Failed to fetch from TPP: " + e.getMessage()).toString());
        }
    }

    /**
     * Wallet UI retrieves list of pending delegate requests.
     */
    @GetMapping("/api/delegate-requests")
    public String getDelegateRequests() {
        JSONObject res = new JSONObject();
        res.put("requests", pendingDelegateRequests.values());
        res.put("count", pendingDelegateRequests.size());
        return res.toString();
    }

    /**
     * TPP polling delegate request status.
     * Response: { requestId, status: "PENDING"|"APPROVED"|"REJECTED" }
     */
    @GetMapping("/api/delegate-status/{requestId}")
    public ResponseEntity<String> getDelegateStatus(@PathVariable String requestId) {
        JSONObject request = pendingDelegateRequests.get(requestId);
        if (request == null) {
            return ResponseEntity.status(404)
                .body(new JSONObject().put("error", "Request not found").toString());
        }
        JSONObject res = new JSONObject();
        res.put("requestId", requestId);
        res.put("status", request.getString("status"));
        res.put("tppClientId", request.getString("tppClientId"));
        if (request.has("approvedScopes")) {
            res.put("approvedScopes", request.getJSONArray("approvedScopes"));
        }
        if (request.has("rejectedAt")) {
            res.put("rejectedAt", request.getString("rejectedAt"));
        }
        return ResponseEntity.ok(res.toString());
    }

    /**
     * User at Wallet UI approves or rejects delegate request.
     * Body approve: { requestId, authzVcJti, approvedScopes: [...] }
     * Body reject:  { requestId, rejected: true }
     */
    @PostMapping("/api/approve-delegate")
    public ResponseEntity<String> approveDelegate(@RequestBody String bodyStr) {
        try {
            JSONObject body = new JSONObject(bodyStr);
            String requestId = body.getString("requestId");
            JSONObject request = pendingDelegateRequests.get(requestId);
            if (request == null) {
                return ResponseEntity.status(404)
                    .body(new JSONObject().put("error", "Request not found: " + requestId).toString());
            }

            boolean rejected = body.optBoolean("rejected", false);
            if (rejected) {
                request.put("status", "REJECTED");
                request.put("rejectedAt", new Date().toString());
                logProtocol("Delegate Rejected", "internal",
                    "User rejected delegate request from TPP: " + request.getString("tppClientId"), null);
                return ResponseEntity.ok(new JSONObject().put("requestId", requestId).put("status", "REJECTED").toString());
            }

            // Approve flow
            String authzVcJti = body.optString("authzVcJti", "");
            List<String> approvedScopes = new ArrayList<>();
            if (body.has("approvedScopes") && body.getJSONArray("approvedScopes") != null) {
                body.getJSONArray("approvedScopes").forEach(s -> approvedScopes.add(s.toString()));
            }

            if (approvedScopes.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(new JSONObject().put("error", "Must approve at least one scope").toString());
            }

            JSONObject tppPublicJwk = request.optJSONObject("tppPublicJwk");

            String delegateVcJti = null;
            if (!approvedScopes.isEmpty() || !authzVcJti.isEmpty()) {
                if (authzVcJti.isEmpty() || "auto-root".equals(authzVcJti)) {
                    authzVcJti = "";
                    for (JSONObject vc : vcs.values()) {
                        if ("AuthorizationCredential".equals(vc.optString("type", ""))) {
                            authzVcJti = vc.optString("jti", "");
                            break;
                        }
                    }
                }
                if (authzVcJti.isEmpty()) {
                    authzVcJti = ensureAuthorizationVc();
                }
                if (!authzVcJti.isEmpty()) {
                    String delegateResult = buildAndStoreDelegateVc(
                        authzVcJti, request.getString("tppClientId"), tppPublicJwk, approvedScopes, request.optJSONObject("challenge"));
                    JSONObject delegateData = new JSONObject(delegateResult);
                    if (!delegateData.has("error")) {
                        delegateVcJti = delegateData.getString("jti");
                    }
                }
            }

            // Update request status
            JSONArray approvedScopesArr = new JSONArray(approvedScopes);
            request.put("status", "APPROVED");
            request.put("approvedScopes", approvedScopesArr);
            request.put("approvedAt", new Date().toString());
            if (delegateVcJti != null) request.put("delegateVcJti", delegateVcJti);
            if (!authzVcJti.isEmpty()) request.put("authzVcJti", authzVcJti);

            logProtocol("Delegate Approved", "internal",
                "User approved delegate for TPP: " + request.getString("tppClientId") +
                    ", scopes: " + approvedScopes.toString(), null);

            JSONObject res = new JSONObject();
            res.put("requestId", requestId);
            res.put("status", "APPROVED");
            res.put("approvedScopes", approvedScopesArr);
            if (delegateVcJti != null) res.put("delegateVcJti", delegateVcJti);
            if (request.has("tpp_redirect_uri")) res.put("tppRedirectUri", request.getString("tpp_redirect_uri"));

            // ── OID4VP Auto-Submit VP directly to TPP ────────────
            String targetTppUrl = (tppUrl != null && !tppUrl.trim().isEmpty()) ? tppUrl.trim() : request.optString("tppUrl", "");
            if (targetTppUrl != null && !targetTppUrl.isEmpty()) {
                if (targetTppUrl.contains("localhost") || targetTppUrl.contains("127.0.0.1")) {
                    targetTppUrl = targetTppUrl.replaceAll("localhost|127\\.0\\.0\\.1", "host.docker.internal");
                }
                try {
                    JSONObject submitPayload = new JSONObject();
                    submitPayload.put("requestId", requestId);
                    submitPayload.put("wallet_key_id", cryptoService.getEcJwk().getKeyID());
                    submitPayload.put("approvedScopes", approvedScopesArr);

                    if (delegateVcJti != null) {
                        JSONObject dvc = vcs.get(delegateVcJti);
                        if (dvc != null) submitPayload.put("delegate_vc", dvc.getString("sdJwt"));
                    }
                    if (!authzVcJti.isEmpty()) {
                        JSONObject avc = vcs.get(authzVcJti);
                        if (avc != null) submitPayload.put("authorization_vc", selectRootPresentation(avc.getString("sdJwt")));
                    }

                    // Build PQC DAS-only encrypted package (F3-03)
                    String rDasVal = request.has("challenge") && request.getJSONObject("challenge").has("r_das")
                            ? request.getJSONObject("challenge").getString("r_das") : "";
                    String dasPkg = buildDasEncryptedPackage(request.getString("tppClientId"), rDasVal, authzVcJti);
                    if (dasPkg != null) {
                        submitPayload.put("das_encrypted_package", dasPkg);
                        request.put("das_encrypted_package", dasPkg);
                        res.put("das_encrypted_package", dasPkg);
                    }

                    String submitUrl = targetTppUrl + "/api/public/submit-presentation";
                    HttpHeaders submitHeaders = new HttpHeaders();
                    submitHeaders.setContentType(MediaType.APPLICATION_JSON);

                    logProtocol("Submitting Presentation (OID4VP)", "outgoing",
                        "Pushing signed Verifiable Presentation to TPP at " + submitUrl, null);

                    pqcRestTemplate.getRestTemplate().postForEntity(
                        submitUrl, new HttpEntity<>(submitPayload.toString(), submitHeaders), String.class);

                    res.put("tppSubmitted", true);
                    logProtocol("Presentation Submitted Successfully", "outgoing",
                        "TPP acknowledged receipt of Verifiable Presentation", null);
                } catch (Exception pushEx) {
                    System.err.println("[Wallet] Note: Auto-submit presentation to TPP: " + pushEx.getMessage());
                    res.put("tppSubmitted", false);
                    res.put("tppSubmitWarning", pushEx.getMessage());
                }
            }

            return ResponseEntity.ok(res.toString());

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500)
                .body(new JSONObject().put("error", e.getMessage()).toString());
        }
    }

    /**
     * TPP retrieves VCs after request is APPROVED.
     * Response: { authorization_vc, delegate_vc, wallet_key_id, wallet_pqc_key }
     */
    @GetMapping("/api/delegate-vcs/{requestId}")
    public ResponseEntity<String> getDelegateVcs(@PathVariable String requestId) {
        JSONObject request = pendingDelegateRequests.get(requestId);
        if (request == null) {
            return ResponseEntity.status(404)
                .body(new JSONObject().put("error", "Request not found").toString());
        }
        if (!"APPROVED".equals(request.getString("status"))) {
            return ResponseEntity.status(400)
                .body(new JSONObject().put("error", "Request not approved yet").put("status", request.getString("status")).toString());
        }

        String authzVcJti = request.optString("authzVcJti", "");
        String delegateVcJti = request.optString("delegateVcJti", "");

        JSONObject authzVc = !authzVcJti.isEmpty() ? vcs.get(authzVcJti) : null;
        JSONObject delegateVc = !delegateVcJti.isEmpty() ? vcs.get(delegateVcJti) : null;

        JSONObject res = new JSONObject();
        if (authzVc != null) res.put("authorization_vc", selectRootPresentation(authzVc.getString("sdJwt")));
        if (delegateVc != null) res.put("delegate_vc", delegateVc.getString("sdJwt"));
        if (request.has("das_encrypted_package")) {
            res.put("das_encrypted_package", request.getString("das_encrypted_package"));
        }
        res.put("wallet_key_id", cryptoService.getEcJwk().getKeyID());
        res.put("wallet_pqc_key", cryptoService.getPqcPublicKeyBase64());
        return ResponseEntity.ok(res.toString());
    }

    // ── Send to TPP (legacy / manual flow) ───────────────────
    @PostMapping("/api/send-to-tpp")
    public String sendToTpp(@RequestBody String bodyStr) {
        JSONObject body = new JSONObject(bodyStr);
        String tppReceiveUrl = body.has("tppReceiveUrl") ? body.getString("tppReceiveUrl") : tppUrl + "/api/receive-vcs";

        JSONObject payload = new JSONObject();
        if (body.has("authzVcJti") && vcs.containsKey(body.getString("authzVcJti"))) {
            payload.put("authorization_vc", selectRootPresentation(vcs.get(body.getString("authzVcJti")).getString("sdJwt")));
        }
        if (body.has("delegateVcJti") && vcs.containsKey(body.getString("delegateVcJti"))) {
            payload.put("delegate_vc", vcs.get(body.getString("delegateVcJti")).getString("sdJwt"));
        }
        payload.put("wallet_key_id", cryptoService.getEcJwk().getKeyID());
        payload.put("wallet_pqc_key", cryptoService.getPqcPublicKeyBase64());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        logProtocol("Sending VCs to TPP", "outgoing", "Sending via PQC mTLS", null);

        ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().postForEntity(
            tppReceiveUrl, new HttpEntity<>(payload.toString(), headers), String.class);

        JSONObject response = new JSONObject();
        response.put("success", res.getStatusCode().is2xxSuccessful());
        return response.toString();
    }

    private String selectRootPresentation(String sdJwt) {
        String[] parts = sdJwt.split("~");
        StringBuilder selected = new StringBuilder(parts[0]);
        for (int i = 1; i < parts.length; i++) {
            if (parts[i].isEmpty()) continue;
            try {
                JSONArray disclosure = new JSONArray(new String(
                    Base64.getUrlDecoder().decode(parts[i]), StandardCharsets.UTF_8));
                if (disclosure.length() == 3 && "scopes".equals(disclosure.getString(1))) {
                    selected.append('~').append(parts[i]);
                }
            } catch (Exception malformedDisclosure) {
                throw new IllegalArgumentException("Malformed Root VC disclosure", malformedDisclosure);
            }
        }
        return selected.toString();
    }

    // ── Protocol Log ──────────────────────────────────────────
    @GetMapping(value = "/api/protocol-log", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getProtocolLog() {
        JSONObject res = new JSONObject();
        synchronized (protocolLog) {
            res.put("entries", protocolLog);
            res.put("total", protocolLog.size());
        }
        return res.toString();
    }

    @DeleteMapping(value = "/api/protocol-log", produces = MediaType.APPLICATION_JSON_VALUE)
    public String clearProtocolLog() {
        synchronized (protocolLog) {
            protocolLog.clear();
        }
        return new JSONObject().put("message", "cleared").toString();
    }

    // ── Helpers ───────────────────────────────────────────────

    private String fetchBankKemKey() {
        try {
            String jwksUrl = bankIssuerUrl + "/jwks";
            ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(jwksUrl, String.class);
            JSONObject jwksJson = new JSONObject(res.getBody());
            JSONArray keys = jwksJson.getJSONArray("keys");
            if (keys.length() > 0) {
                JSONObject firstKey = keys.getJSONObject(0);
                if (firstKey.has("pqc_keys") && firstKey.getJSONObject("pqc_keys").has("MLKEM768")) {
                    return firstKey.getJSONObject("pqc_keys").getString("MLKEM768");
                }
            }
        } catch (Exception e) {
            System.err.println("[Wallet] Error fetching bank KEM key: " + e.getMessage());
            throw new IllegalStateException("Failed to fetch Bank ML-KEM-768 public key: " + e.getMessage(), e);
        }
        throw new IllegalStateException("Bank Issuer JWKS does not contain ML-KEM-768 public key");
    }

    private String buildDasEncryptedPackage(String tppClientId, String rDas, String authzVcJti) {
        try {
            String bankKemKey = fetchBankKemKey();

            JSONObject sensitivePayload = new JSONObject();
            sensitivePayload.put("tpp_client_id", tppClientId);
            sensitivePayload.put("r_das", rDas != null ? rDas : "");
            sensitivePayload.put("authz_vc_jti", authzVcJti != null ? authzVcJti : "");
            sensitivePayload.put("iat", System.currentTimeMillis() / 1000);
            
            JSONObject dasOnlyClaims = new JSONObject();
            dasOnlyClaims.put("holder_account_tax_id", "TAX-99881122");
            dasOnlyClaims.put("internal_risk_tier", "LOW_RISK");
            sensitivePayload.put("das_only_claims", dasOnlyClaims);

            byte[] pubBytes = Base64.getUrlDecoder().decode(bankKemKey);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("ML-KEM", "BC");
            java.security.PublicKey bankKemPub = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(pubBytes));

            javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("ML-KEM", "BC");
            kg.init(new org.bouncycastle.jcajce.spec.KEMGenerateSpec(bankKemPub, "AES"));
            org.bouncycastle.jcajce.SecretKeyWithEncapsulation secEnc = (org.bouncycastle.jcajce.SecretKeyWithEncapsulation) kg.generateKey();
            byte[] kemCt = secEnc.getEncapsulation();
            javax.crypto.SecretKey sharedSecret = secEnc;

            byte[] iv = new byte[12];
            new java.security.SecureRandom().nextBytes(iv);

            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            javax.crypto.spec.GCMParameterSpec spec = new javax.crypto.spec.GCMParameterSpec(128, iv);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, sharedSecret, spec);

            byte[] combined = cipher.doFinal(sensitivePayload.toString().getBytes(StandardCharsets.UTF_8));
            int ctLen = combined.length - 16;
            byte[] ct = new byte[ctLen];
            byte[] tag = new byte[16];
            System.arraycopy(combined, 0, ct, 0, ctLen);
            System.arraycopy(combined, ctLen, tag, 0, 16);

            JSONObject pkg = new JSONObject();
            pkg.put("alg", "ML-KEM-768+AES-256-GCM");
            pkg.put("recipient_kid", "bank-kem-key");
            pkg.put("kem_ct", Base64.getEncoder().encodeToString(kemCt));
            pkg.put("iv", Base64.getEncoder().encodeToString(iv));
            pkg.put("ciphertext", Base64.getEncoder().encodeToString(ct));
            pkg.put("tag", Base64.getEncoder().encodeToString(tag));

            return pkg.toString();
        } catch (Exception e) {
            System.err.println("[Wallet] Failed to build PQC DAS encrypted package: " + e.getMessage());
            return null;
        }
    }

    /**
     * Build, sign (Hybrid) and store a Delegate VC in the wallet.
     * Returns JSON string of the result or error.
     */
    private String buildAndStoreDelegateVc(String authzVcJti, String tppClientId,
                                            JSONObject tppPublicKey, List<String> delegatedScopes) {
        return buildAndStoreDelegateVc(authzVcJti, tppClientId, tppPublicKey, delegatedScopes, null);
    }

    private String buildAndStoreDelegateVc(String authzVcJti, String tppClientId,
                                            JSONObject tppPublicKey, List<String> delegatedScopes,
                                            JSONObject challenge) {
        try {
            String jti = "urn:uuid:" + UUID.randomUUID().toString();
            long now = System.currentTimeMillis() / 1000;

            // The classical half of the wallet key. The composite (PQC) half is carried once, in wallet_pqc_pub.
            JSONObject walletEcPublicJwk = new JSONObject(
                    cryptoService.getEcJwk().toPublicJWK().toJSONString());

            JSONObject payload = new JSONObject();
            payload.put("iss", cryptoService.getEcJwk().getKeyID());
            payload.put("sub", tppClientId);
            payload.put("iat", now);
            payload.put("exp", now + 86400);
            payload.put("jti", jti);
            payload.put("vct", "DelegatedAuthorizationCredential");
            payload.put("parent_vc_jti", authzVcJti);
            payload.put("delegated_scopes", new JSONArray(delegatedScopes));
            payload.put("wallet_pqc_pub", cryptoService.getPqcPublicKeyBase64());
            payload.put("wallet_ec_jwk", walletEcPublicJwk);  // with wallet_pqc_pub: the two halves of the hybrid key
            if (tppPublicKey != null) {
                payload.put("cnf", new JSONObject().put("jwk", tppPublicKey));
            }

            // VDAM Invariant Inclusions (Equation 4.2 & 6.6)
            if (challenge != null) {
                if (challenge.has("r_das")) payload.put("r_das", challenge.getString("r_das"));
                if (challenge.has("aud_r")) payload.put("aud_r", challenge.getString("aud_r"));
                if (challenge.has("aud_g")) payload.put("aud_g", challenge.getString("aud_g"));
            }

            // Open Banking UK Delegated Consent Object
            JSONObject delegatedConsent = new JSONObject();
            delegatedConsent.put("ConsentId", "urn:uk:obie:delegated-consent:" + UUID.randomUUID().toString());
            delegatedConsent.put("Status", "Authorised");
            delegatedConsent.put("CreationDateTime", new Date().toString());
            delegatedConsent.put("Permissions", new JSONArray(delegatedScopes));
            delegatedConsent.put("ExpirationDateTime", new Date(System.currentTimeMillis() + 86400 * 1000L).toString());
            delegatedConsent.put("purpose", "TPP Delegated Open Banking Access");
            delegatedConsent.put("delegate_tpp", tppClientId);
            payload.put("consent", delegatedConsent);

            String delegateJwt = cryptoService.signHybrid(payload.toString(), "vc+sd-jwt");

            // RFC 9901 Key Binding JWT (KB-JWT) with SHA-384 digest per PQC design specification
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-384");
            byte[] hash = md.digest((delegateJwt + "~").getBytes(StandardCharsets.UTF_8));
            String sdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);

            JSONObject kbPayload = new JSONObject();
            kbPayload.put("iat", now);
            kbPayload.put("aud", challenge != null && challenge.has("aud_kb") ? challenge.getString("aud_kb") : "http://localhost:7000/verify-kb");
            kbPayload.put("nonce", challenge != null && challenge.has("nonce") ? challenge.getString("nonce") : UUID.randomUUID().toString());
            kbPayload.put("sd_hash", sdHash);

            String kbJwt = cryptoService.signHybrid(kbPayload.toString(), "kb+jwt");
            String sdJwt = delegateJwt + "~" + kbJwt;

            JSONObject vc = new JSONObject();
            vc.put("jti", jti);
            vc.put("type", "DelegatedAuthorizationCredential");
            vc.put("sdJwt", sdJwt);
            vc.put("payload", payload);
            vc.put("disclosedClaims", new JSONObject());
            vc.put("receivedAt", new Date().toString());
            vcs.put(jti, vc);

            logProtocol("Delegate VC Created", "internal",
                "Hybrid signed Delegate VC for TPP: " + tppClientId + " scopes: " + delegatedScopes + " with RFC 9901 Key Binding", null);

            JSONObject res = new JSONObject();
            res.put("jti", jti);
            res.put("delegateSdJwt", sdJwt);
            res.put("delegatedScopes", new JSONArray(delegatedScopes));
            return res.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return new JSONObject().put("error", e.getMessage()).toString();
        }
    }

    /**
     * Parse SD-JWT disclosures into a plain claims map.
     */
    private JSONObject parseDisclosures(String sdJwt) {
        JSONObject claims = new JSONObject();
        try {
            String[] parts = sdJwt.split("~");
            for (int i = 1; i < parts.length; i++) {
                if (parts[i].isEmpty()) continue;
                byte[] decoded = Base64.getUrlDecoder().decode(parts[i]);
                JSONArray arr = new JSONArray(new String(decoded, StandardCharsets.UTF_8));
                if (arr.length() == 3) {
                    String key = arr.getString(1);
                    Object value = arr.get(2);
                    claims.put(key, value);
                }
            }
        } catch (Exception e) {
            System.err.println("[Wallet] parseDisclosures error: " + e.getMessage());
        }
        return claims;
    }

    /**
     * Perform Selective Disclosure by stripping out disclosures not in the allowed list.
     */
    private String performSelectiveDisclosure(String sdJwt, List<String> allowedClaims) {
        try {
            String[] parts = sdJwt.split("~");
            if (parts.length < 2) return sdJwt;
            
            StringBuilder newSdJwt = new StringBuilder(parts[0]);
            
            for (int i = 1; i < parts.length; i++) {
                if (parts[i].isEmpty()) continue;
                byte[] decoded = Base64.getUrlDecoder().decode(parts[i]);
                JSONArray arr = new JSONArray(new String(decoded, StandardCharsets.UTF_8));
                if (arr.length() == 3) {
                    String key = arr.getString(1);
                    if (allowedClaims.contains(key)) {
                        newSdJwt.append("~").append(parts[i]);
                    }
                }
            }
            newSdJwt.append("~");
            return newSdJwt.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return sdJwt;
        }
    }
}
