package com.bk.research.pqc.tpp;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import com.nimbusds.jose.jwk.ECKey;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@CrossOrigin(origins = "*")
public class TppController {

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private PqcRestTemplate pqcRestTemplate;

    @Value("${CLIENT_ID:tpp-demo-client}")
    private String clientId;

    @Value("${BANK_ISSUER_URL:http://oqs-tpp-outbound:19443}")
    private String bankIssuerUrl;

    @Value("${DIRECT_BANK_ISSUER_URL:http://bank-issuer:7000}")
    private String directBankIssuerUrl;

    @Value("${RESOURCE_SERVER_URL:http://oqs-tpp-outbound:19443}")
    private String resourceServerUrl;

    @Value("${WALLET_URL:http://oqs-tpp-outbound:15443}")
    private String walletUrl;

    // Authorization state is kept per request (keyed by requestId), never per process. A single
    // shared map let concurrent delegations overwrite each other's VCs, challenge, and token.
    private static final int MAX_TRACKED_REQUESTS = 20000;
    private final Map<String, Map<String, JSONObject>> requestStates = new ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentLinkedQueue<String> requestOrder = new java.util.concurrent.ConcurrentLinkedQueue<>();
    // Most recent request. Used only by callers that send no requestId (the single-user demo UI).
    private volatile String currentRequestId = null;
    private final List<JSONObject> protocolLog = new ArrayList<>();

    // ── Per-request state ─────────────────────────────────────
    /** Registers a request and evicts the oldest ones so per-request state cannot grow without bound. */
    private void registerRequest(String requestId) {
        if (requestStates.putIfAbsent(requestId, new ConcurrentHashMap<>()) == null) {
            requestOrder.add(requestId);
            while (requestOrder.size() > MAX_TRACKED_REQUESTS) {
                String oldest = requestOrder.poll();
                if (oldest == null) break;
                requestStates.remove(oldest);
                pendingRequests.remove(oldest);
            }
        }
    }

    /** An explicit requestId wins; without one, fall back to the most recent request (demo UI only). */
    private String resolveRequestId(String requestId) {
        return (requestId == null || requestId.isEmpty()) ? currentRequestId : requestId;
    }

    /** State of one request, for writing. Created on first use. */
    private Map<String, JSONObject> stateFor(String requestId) {
        String id = resolveRequestId(requestId);
        if (id == null) return new ConcurrentHashMap<>();
        registerRequest(id);
        Map<String, JSONObject> state = requestStates.get(id);
        return state != null ? state : new ConcurrentHashMap<>();
    }

    /** State of one request, for reading. Never creates an entry. */
    private Map<String, JSONObject> peekState(String requestId) {
        String id = resolveRequestId(requestId);
        Map<String, JSONObject> state = id == null ? null : requestStates.get(id);
        return state != null ? state : new ConcurrentHashMap<>();
    }

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
            if (protocolLog.size() > 200) protocolLog.remove(protocolLog.size() - 1);
        }
        System.out.println("[TPP][" + step + "] " + desc);
    }

    // ── Config ────────────────────────────────────────────────
    @GetMapping(value = "/api/config", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getConfig() {
        JSONObject res = new JSONObject();
        res.put("clientId", clientId);
        res.put("bankIssuerUrl", bankIssuerUrl);
        res.put("resourceServerUrl", resourceServerUrl);
        res.put("walletUrl", walletUrl);
        res.put("tppKeyId", cryptoService.getEcJwk().getKeyID());
        JSONObject tppJwk = new JSONObject(cryptoService.getEcJwk().toPublicJWK().toJSONString());
        tppJwk.put("composite_pub", cryptoService.getCompositePublicKeyBase64());
        tppJwk.put("alg", "MLDSA65-ECDSA-P384-SHA512");
        res.put("tppPublicJwk", tppJwk);
        return res.toString();
    }

    // ── Delegate Request Flow (TPP-initiated) ─────────────────

    // TPP Scope Privacy Discovery: Fetch ONLY this TPP's permitted scopes (S_T) from Bank Policy Engine
    @GetMapping(value = "/api/tpp-allowed-scopes", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getTppAllowedScopes() {
        try {
            String policyUrl = directBankIssuerUrl + "/api/policy/tpp-scopes/" + clientId;
            ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(policyUrl, String.class);
            JSONObject data = new JSONObject(res.getBody());
            data.put("source", "BANK_POLICY_ENGINE");
            data.put("status", "SUCCESS");
            return ResponseEntity.ok(data.toString());
        } catch (Exception e1) {
            System.err.println("[TPP Policy Discovery] Failed to fetch via direct URL (" + directBankIssuerUrl + "): " + e1.getMessage());
            try {
                String policyUrl = bankIssuerUrl + "/api/policy/tpp-scopes/" + clientId;
                ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(policyUrl, String.class);
                JSONObject data = new JSONObject(res.getBody());
                data.put("source", "BANK_POLICY_ENGINE");
                data.put("status", "SUCCESS");
                return ResponseEntity.ok(data.toString());
            } catch (Exception e2) {
                System.err.println("[TPP Policy Discovery] Failed to fetch via proxy URL (" + bankIssuerUrl + "): " + e2.getMessage());
                JSONObject fallback = new JSONObject();
                fallback.put("tpp_client_id", clientId);
                fallback.put("source", "FALLBACK");
                fallback.put("status", "WARNING");
                fallback.put("warning", "Bank Policy Engine unreachable (" + e2.getMessage() + ")");
                fallback.put("allowed_scopes", new JSONArray(Arrays.asList(
                    "accounts:read", "transfers:read", "transfers:write", "profile:read",
                    "transactions:read",
                    "ReadAccountsBasic", "ReadAccountsDetail", "ReadBalances",
                    "ReadTransactionsBasic", "ReadTransactionsDetail", "CreateDomesticPayment")));
                return ResponseEntity.ok(fallback.toString());
            }
        }
    }

    // Dynamic Identity Claims Discovery: Fetch allowed identity profile claims schema from Bank Policy Engine
    @GetMapping(value = "/api/tpp-allowed-identity-claims", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getTppAllowedIdentityClaims() {
        try {
            String policyUrl = directBankIssuerUrl + "/api/policy/identity-claims";
            ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(policyUrl, String.class);
            JSONObject data = new JSONObject(res.getBody());
            data.put("source", "BANK_POLICY_ENGINE");
            data.put("status", "SUCCESS");
            return ResponseEntity.ok(data.toString());
        } catch (Exception e1) {
            try {
                String policyUrl = bankIssuerUrl + "/api/policy/identity-claims";
                ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(policyUrl, String.class);
                JSONObject data = new JSONObject(res.getBody());
                data.put("source", "BANK_POLICY_ENGINE");
                data.put("status", "SUCCESS");
                return ResponseEntity.ok(data.toString());
            } catch (Exception e2) {
                JSONObject fallback = new JSONObject();
                fallback.put("source", "FALLBACK");
                fallback.put("status", "WARNING");
                fallback.put("warning", "Bank Policy Engine unreachable (" + e2.getMessage() + ")");
                fallback.put("claims", new JSONArray(Arrays.asList("name", "email", "dob", "nationalId", "address", "phoneNumber")));
                return ResponseEntity.ok(fallback.toString());
            }
        }
    }

    /**
     * TPP sends Delegate VC request to Wallet.
     * Body: { requestedScopes: [...], walletUrl (optional, override) }
     * Response: { requestId, status: "PENDING" }
     */
    private final Map<String, JSONObject> pendingRequests = new ConcurrentHashMap<>();

    /**
     * TPP sends Delegate VC request to Wallet (or creates pending OID4VP request).
     * Body: { requestedScopes: [...], walletUrl (optional, override) }
     * Response: { requestId, status: "PENDING" }
     */
    @PostMapping(value = "/api/request-delegate", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> requestDelegate(@RequestBody String bodyStr) {
        try {
            JSONObject body = new JSONObject(bodyStr);
            String targetWalletUrl = body.optString("walletUrl", walletUrl);
            String requestType = body.optString("requestType", "BOTH");
            JSONArray requestedScopes = body.optJSONArray("requestedScopes");

            JSONObject tppPublicJwk = new JSONObject(
                cryptoService.getEcJwk().toPublicJWK().toJSONString());
            tppPublicJwk.put("composite_pub", cryptoService.getCompositePublicKeyBase64());
            tppPublicJwk.put("alg", "MLDSA65-ECDSA-P384-SHA512");

            String requestId = UUID.randomUUID().toString();
            Map<String, JSONObject> tppState = stateFor(requestId);
            currentRequestId = requestId;

            JSONObject requestPayload = new JSONObject();
            requestPayload.put("requestId", requestId);
            requestPayload.put("tppClientId", clientId);
            requestPayload.put("requestType", requestType);
            requestPayload.put("tppPublicJwk", tppPublicJwk);
            requestPayload.put("createdAt", new Date().toString());
            requestPayload.put("status", "PENDING");
            String redirectUri = body.optString("redirect_uri", body.optString("tpp_redirect_uri", ""));
            if (!redirectUri.isEmpty()) {
                requestPayload.put("tpp_redirect_uri", redirectUri);
            }

            if (requestedScopes == null || requestedScopes.isEmpty()) {
                try {
                    String policyUrl = directBankIssuerUrl + "/api/policy/tpp-scopes/" + clientId;
                    ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(policyUrl, String.class);
                    JSONObject policyData = new JSONObject(res.getBody());
                    requestedScopes = policyData.optJSONArray("allowed_scopes");
                } catch (Exception e) {
                    requestedScopes = new JSONArray(Arrays.asList(
                        "ReadAccountsDetail", "ReadBalances", "ReadTransactionsDetail", "CreateDomesticPayment",
                        "accounts:read", "transfers:read", "transfers:write"));
                }
            }
            requestPayload.put("requestedScopes", requestedScopes);

            // Pre-F2 Challenge Flow (VDAM Specification Section 6.2 & Flow F1/F2)
            try {
                JSONObject chReq = new JSONObject();
                chReq.put("tpp_client_id", clientId);
                chReq.put("aud_r", "http://localhost:4000");

                HttpHeaders chHeaders = new HttpHeaders();
                chHeaders.setContentType(MediaType.APPLICATION_JSON);

                ResponseEntity<String> chRes = pqcRestTemplate.getRestTemplate().postForEntity(
                    directBankIssuerUrl + "/api/v1/challenge",
                    new HttpEntity<>(chReq.toString(), chHeaders),
                    String.class);

                if (chRes.getStatusCode().is2xxSuccessful()) {
                    JSONObject chData = new JSONObject(chRes.getBody());
                    requestPayload.put("ch_das", chData.optString("ch_das"));
                    requestPayload.put("challenge", chData.optJSONObject("challenge"));
                    tppState.put("challengeData", chData);
                    logProtocol("DAS Challenge Acquired", "incoming",
                        "Obtained signed Pre-F2 challenge from Bank Issuer DAS", chData);
                }
            } catch (Exception chEx) {
                System.out.println("[TPP] Pre-F2 challenge fetch skipped or offline: " + chEx.getMessage());
            }

            // Store in TPP state for both pull and push modes
            pendingRequests.put(requestId, requestPayload);
            tppState.put("delegateRequestId", new JSONObject().put("requestId", requestId));
            tppState.put("delegateWalletUrl", new JSONObject().put("url", targetWalletUrl));

            logProtocol("Delegate Request Created", "outgoing",
                "Created " + requestType + " request (ID: " + requestId + ")",
                requestPayload);

            // OID4VP Model: Wallet acts as Edge Client (no inbound listening port).
            // Request is staged in pendingRequests and retrieved by Wallet via GET /api/public/delegate-request/{requestId}.
            logProtocol("Delegate Request Staged (OID4VP)", "internal",
                "Ready for Wallet pull via OID4VP (Request ID: " + requestId + ")", requestPayload);

            JSONObject resData = new JSONObject();
            resData.put("requestId", requestId);
            resData.put("status", "PENDING");
            resData.put("tppClientId", clientId);
            resData.put("requestPayload", requestPayload);
            return ResponseEntity.ok(resData.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500)
                .body(new JSONObject().put("error", e.getMessage()).toString());
        }
    }

    @PostMapping(value = "/api/wallet-approve", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> approveInWallet(@RequestBody String bodyStr) {
        try {
            JSONObject body = new JSONObject(bodyStr);
            String reqId = body.optString("requestId", "");
            Map<String, JSONObject> tppState = peekState(reqId);
            JSONArray approvedScopes = body.optJSONArray("approvedScopes");

            JSONObject payload = new JSONObject();
            payload.put("requestId", reqId);
            if (approvedScopes != null) {
                payload.put("approvedScopes", approvedScopes);
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            String targetWalletUrl = walletUrl;
            if (tppState.containsKey("delegateWalletUrl")) {
                targetWalletUrl = tppState.get("delegateWalletUrl").optString("url", walletUrl);
            }

            String approveUrl = targetWalletUrl + "/api/approve-delegate";
            logProtocol("Forwarding Approval to Wallet", "outgoing", "Approving request " + reqId + " via " + approveUrl, payload);

            ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().postForEntity(
                approveUrl, new HttpEntity<>(payload.toString(), headers), String.class);

            return ResponseEntity.status(res.getStatusCode()).body(res.getBody());
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new JSONObject().put("error", "Approve forward failed: " + e.getMessage()).toString());
        }
    }

    /**
     * OID4VP Endpoint: Wallet fetches the pending delegation request from TPP.
     */
    @GetMapping(value = "/api/public/delegate-request/{requestId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getPublicDelegateRequest(@PathVariable("requestId") String requestId) {
        JSONObject req = pendingRequests.get(requestId);
        if (req != null) {
            return ResponseEntity.ok(req.toString());
        }
        JSONObject curReq = peekState(requestId).get("delegateRequestId");
        if (curReq != null && requestId.equals(curReq.optString("requestId"))) {
            JSONObject fallbackReq = new JSONObject();
            fallbackReq.put("requestId", requestId);
            fallbackReq.put("tppClientId", clientId);
            JSONObject tppJwk = new JSONObject(cryptoService.getEcJwk().toPublicJWK().toJSONString());
            tppJwk.put("composite_pub", cryptoService.getCompositePublicKeyBase64());
            tppJwk.put("alg", "MLDSA65-ECDSA-P384-SHA512");
            fallbackReq.put("tppPublicJwk", tppJwk);
            fallbackReq.put("status", "PENDING");
            return ResponseEntity.ok(fallbackReq.toString());
        }
        return ResponseEntity.status(404).body(new JSONObject().put("error", "Request not found: " + requestId).toString());
    }

    private ECKey getBankJwksKey() {
        try {
            String jwksUrl = directBankIssuerUrl + "/jwks";
            ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(jwksUrl, String.class);
            JSONObject jwks = new JSONObject(res.getBody());
            JSONArray keys = jwks.optJSONArray("keys");
            if (keys != null && keys.length() > 0) {
                return ECKey.parse(keys.getJSONObject(0).toString());
            }
        } catch (Exception e1) {
            try {
                String jwksUrl = bankIssuerUrl + "/jwks";
                ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(jwksUrl, String.class);
                JSONObject jwks = new JSONObject(res.getBody());
                JSONArray keys = jwks.optJSONArray("keys");
                if (keys != null && keys.length() > 0) {
                    return ECKey.parse(keys.getJSONObject(0).toString());
                }
            } catch (Exception e2) {
                System.err.println("[TPP PQC] Failed to fetch Bank JWKS: " + e2.getMessage());
            }
        }
        return null;
    }

    private byte[] getBankCompositePubKey() {
        try {
            String[] urls = new String[]{directBankIssuerUrl + "/jwks", bankIssuerUrl + "/jwks"};
            for (String u : urls) {
                try {
                    ResponseEntity<String> res = pqcRestTemplate.getRestTemplate().getForEntity(u, String.class);
                    JSONObject jwks = new JSONObject(res.getBody());
                    JSONArray keys = jwks.optJSONArray("keys");
                    if (keys != null) {
                        for (int i = 0; i < keys.length(); i++) {
                            JSONObject k = keys.getJSONObject(i);
                            if (k.has("composite_pub")) {
                                return Base64.getUrlDecoder().decode(k.getString("composite_pub"));
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
        return null;
    }

    private boolean verifyAndStoreIncomingVcs(Map<String, JSONObject> tppState, String authzVcStr, String delegateVcStr) {
        long now = System.currentTimeMillis() / 1000;
        String rootJti = null;

        // 1. Verify Root Scope VC (F3-04, C-SIG, N-SCOPE)
        if (authzVcStr != null && !authzVcStr.isEmpty()) {
            try {
                String[] rParts = authzVcStr.split("~")[0].split("\\.");
                if (rParts.length < 3) {
                    System.err.println("[TPP PQC] Root Scope VC is malformed");
                    return false;
                }
                byte[] rPayloadBytes = Base64.getUrlDecoder().decode(rParts[1]);
                JSONObject rPayload = new JSONObject(new String(rPayloadBytes, StandardCharsets.UTF_8));

                // Verify expiration
                if (rPayload.has("exp") && rPayload.getLong("exp") < now) {
                    System.err.println("[TPP PQC] Root Scope VC has expired");
                    return false;
                }
                rootJti = rPayload.optString("jti", null);

                // Verify Bank Issuer Hybrid Signature
                ECKey bankKey = getBankJwksKey();
                byte[] bankCompositePub = getBankCompositePubKey();
                String rSigningInput = rParts[0] + "." + rParts[1];
                byte[] rSigBytes = Base64.getUrlDecoder().decode(rParts[2]);
                boolean bankSigOk = cryptoService.verifyHybridSignature(
                    rSigningInput,
                    rSigBytes,
                    bankKey != null ? bankKey.toECPublicKey() : null,
                    bankCompositePub,
                    "MLDSA65"
                );
                if (!bankSigOk) {
                    System.err.println("[TPP PQC] Root Scope VC hybrid signature verification failed under Bank key");
                    return false;
                }
            } catch (Exception ex) {
                System.err.println("[TPP PQC] Error verifying Root Scope VC: " + ex.getMessage());
                return false;
            }
        }

        // 2. Verify Delegation VC (F3-04, N-DEL, PQC-01 AND-verification)
        if (delegateVcStr != null && !delegateVcStr.isEmpty()) {
            try {
                String[] dParts = delegateVcStr.split("~")[0].split("\\.");
                if (dParts.length < 3) {
                    System.err.println("[TPP PQC] Delegation VC is malformed");
                    return false;
                }
                byte[] payloadBytes = Base64.getUrlDecoder().decode(dParts[1]);
                JSONObject dPayload = new JSONObject(new String(payloadBytes, StandardCharsets.UTF_8));

                // Verify expiration
                if (dPayload.has("exp") && dPayload.getLong("exp") < now) {
                    System.err.println("[TPP PQC] Delegation VC has expired");
                    return false;
                }

                // Verify parent lineage linkage
                String parentJti = dPayload.optString("parent_vc_jti", "");
                if (rootJti != null && !parentJti.isEmpty() && !parentJti.equals(rootJti)) {
                    System.err.println("[TPP PQC] Delegation VC parent_vc_jti ('" + parentJti + "') does not match Root VC JTI ('" + rootJti + "')");
                    return false;
                }

                // Verify delegate subject matches TPP client ID
                String sub = dPayload.optString("sub", "");
                if (!sub.isEmpty() && !sub.equals(clientId)) {
                    System.err.println("[TPP PQC] Delegation VC subject ('" + sub + "') does not match TPP client ('" + clientId + "')");
                    return false;
                }

                // Strictly verify wallet hybrid signature (Mandatory in PQC baseline, F-13)
                if (!dPayload.has("wallet_ec_jwk")) {
                    System.err.println("[TPP PQC] Delegation VC rejected: missing mandatory wallet_ec_jwk");
                    return false;
                }
                byte[] walletPqcPub = null;
                if (dPayload.has("wallet_pqc_pub")) {
                    walletPqcPub = Base64.getUrlDecoder().decode(dPayload.getString("wallet_pqc_pub"));
                } else if (dPayload.has("wallet_pqc_key")) {
                    walletPqcPub = Base64.getUrlDecoder().decode(dPayload.getString("wallet_pqc_key"));
                }
                if (walletPqcPub == null || walletPqcPub.length == 0) {
                    System.err.println("[TPP PQC] Delegation VC rejected: missing mandatory wallet_pqc_pub in PQC baseline");
                    return false;
                }

                ECKey walletKey = ECKey.parse(dPayload.getJSONObject("wallet_ec_jwk").toString());
                String dSigningInput = dParts[0] + "." + dParts[1];
                byte[] dSigBytes = Base64.getUrlDecoder().decode(dParts[2]);

                boolean sigValid = cryptoService.verifyHybridSignature(dSigningInput, dSigBytes, walletKey.toECPublicKey(), walletPqcPub, "MLDSA65");
                if (!sigValid) {
                    System.err.println("[TPP PQC] Delegation VC hybrid signature verification failed under Wallet key!");
                    return false;
                }

                // Verify cnf binding matches TPP's public key
                if (dPayload.has("cnf") && dPayload.getJSONObject("cnf").has("jwk")) {
                    JSONObject cnfJwk = dPayload.getJSONObject("cnf").getJSONObject("jwk");
                    String cnfKid = cnfJwk.optString("kid", "");
                    String myKid = cryptoService.getEcJwk().getKeyID();
                    if (!cnfKid.isEmpty() && !myKid.isEmpty() && !cnfKid.equals(myKid)) {
                        System.err.println("[TPP PQC] Delegation VC cnf key mismatch! Expected: " + myKid + ", got: " + cnfKid);
                        return false;
                    }
                }
            } catch (Exception ex) {
                System.err.println("[TPP PQC] Error verifying incoming Delegation VC: " + ex.getMessage());
                return false;
            }
        }

        if (authzVcStr != null && !authzVcStr.isEmpty()) {
            tppState.put("authorization_vc", new JSONObject().put("sdJwt", authzVcStr));
        }
        if (delegateVcStr != null && !delegateVcStr.isEmpty()) {
            tppState.put("delegate_vc", new JSONObject().put("sdJwt", delegateVcStr));
        }
        return true;
    }

    /**
     * OID4VP Endpoint: Wallet submits the approved Verifiable Presentation directly to TPP.
     */
    @PostMapping(value = "/api/public/submit-presentation", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> submitPresentation(@RequestBody String bodyStr) {
        try {
            JSONObject body = new JSONObject(bodyStr);
            String requestId = body.optString("requestId", "");
            Map<String, JSONObject> tppState = stateFor(requestId);
            
            String authzVc = body.optString("authorization_vc", null);
            String delegateVc = body.optString("delegate_vc", null);

            boolean verified = verifyAndStoreIncomingVcs(tppState, authzVc, delegateVc);
            if (!verified) {
                logProtocol("Presentation Rejected", "incoming", "Presentation rejected due to cryptographic or binding mismatch", body);
                return ResponseEntity.status(401).body(new JSONObject().put("error", "presentation_verification_failed").toString());
            }

            tppState.put("walletKeyId", new JSONObject().put("keyId", body.optString("wallet_key_id", "")));
            if (body.has("das_encrypted_package")) {
                tppState.put("das_encrypted_package", new JSONObject().put("pkg", body.getString("das_encrypted_package")));
            }
            if (!requestId.isEmpty()) {
                tppState.put("lastFetchedRequestId", new JSONObject().put("id", requestId));
                JSONObject req = pendingRequests.get(requestId);
                if (req != null) {
                    req.put("status", "APPROVED");
                    req.put("approvedScopes", body.optJSONArray("approvedScopes"));
                }
            }
            tppState.remove("tokenInfo");

            logProtocol("Presentation Received (OID4VP Submission)", "incoming",
                "Wallet successfully submitted Verifiable Presentation for request: " + requestId, body);

            JSONObject res = new JSONObject();
            res.put("success", true);
            res.put("message", "Presentation received and verified successfully");
            res.put("requestId", requestId);
            return ResponseEntity.ok(res.toString());
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(new JSONObject().put("error", e.getMessage()).toString());
        }
    }

    /**
     * TPP polls delegate request status from Wallet (or checks local state).
     * If APPROVED, automatically fetches / confirms VCs.
     */
    @GetMapping(value = "/api/poll-delegate", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> pollDelegateStatus(
            @RequestParam(value = "requestId", required = false) String requestIdParam) {
        try {
            Map<String, JSONObject> tppState = peekState(requestIdParam);
            JSONObject requestIdObj = tppState.get("delegateRequestId");
            if (requestIdObj == null) {
                return ResponseEntity.ok(new JSONObject()
                    .put("status", "NO_REQUEST")
                    .put("message", "No pending delegate request").toString());
            }

            String requestId = requestIdObj.getString("requestId");
            String lastFetched = tppState.containsKey("lastFetchedRequestId") 
                ? tppState.get("lastFetchedRequestId").getString("id") : null;

            // 1. Check if presentation was already submitted directly to TPP via OID4VP
            if (requestId.equals(lastFetched) || tppState.containsKey("delegate_vc")) {
                JSONObject pending = pendingRequests.get(requestId);
                JSONArray scopes = pending != null ? pending.optJSONArray("approvedScopes") : new JSONArray();
                JSONObject statusData = new JSONObject();
                statusData.put("status", "APPROVED");
                statusData.put("requestId", requestId);
                statusData.put("approvedScopes", scopes != null ? scopes : new JSONArray());
                statusData.put("vcsReceived", true);
                return ResponseEntity.ok(statusData.toString());
            }

            // 2. Fallback: Poll status directly from Wallet if reachable
            String targetWalletUrl = tppState.containsKey("delegateWalletUrl")
                ? tppState.get("delegateWalletUrl").getString("url") : walletUrl;

            try {
                ResponseEntity<String> statusRes = pqcRestTemplate.getRestTemplate().getForEntity(
                    targetWalletUrl + "/api/delegate-status/" + requestId, String.class);

                JSONObject statusData = new JSONObject(statusRes.getBody());
                String status = statusData.getString("status");

                if ("APPROVED".equals(status) && !requestId.equals(lastFetched)) {
                    // Fetch VCs from Wallet
                    logProtocol("Fetching Approved VCs", "outgoing",
                        "Request approved, fetching VCs from Wallet", null);

                    ResponseEntity<String> vcsRes = pqcRestTemplate.getRestTemplate().getForEntity(
                        targetWalletUrl + "/api/delegate-vcs/" + requestId, String.class);

                    JSONObject vcsData = new JSONObject(vcsRes.getBody());

                    String authzVc = vcsData.optString("authorization_vc", null);
                    String delegateVc = vcsData.optString("delegate_vc", null);

                    boolean verified = verifyAndStoreIncomingVcs(tppState, authzVc, delegateVc);
                    if (!verified) {
                        logProtocol("VC Verification Failed", "incoming", "Fetched VCs rejected due to cryptographic mismatch", vcsData);
                        return ResponseEntity.status(401).body(new JSONObject().put("error", "vc_verification_failed").toString());
                    }
                    
                    tppState.put("walletKeyId", new JSONObject().put("keyId", vcsData.optString("wallet_key_id")));
                    if (vcsData.has("das_encrypted_package")) {
                        tppState.put("das_encrypted_package", new JSONObject().put("pkg", vcsData.getString("das_encrypted_package")));
                    }
                    tppState.put("lastFetchedRequestId", new JSONObject().put("id", requestId));
                    tppState.remove("tokenInfo");

                    logProtocol("VCs Received from Wallet", "incoming",
                        "Credential payload fetched after user approval", null);

                    statusData.put("vcsReceived", true);
                } else if ("APPROVED".equals(status) && requestId.equals(lastFetched)) {
                    statusData.put("vcsReceived", true);
                }

                return ResponseEntity.ok(statusData.toString());
            } catch (Exception netEx) {
                // Wallet is waiting for user action at local app
                JSONObject statusData = new JSONObject();
                statusData.put("status", "PENDING");
                statusData.put("requestId", requestId);
                statusData.put("message", "Waiting for user approval and presentation submission");
                return ResponseEntity.ok(statusData.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500)
                .body(new JSONObject().put("error", e.getMessage()).toString());
        }
    }

    // ── Receive VCs (legacy / manual push from Wallet) ────────
    @PostMapping(value = "/api/receive-vcs", produces = MediaType.APPLICATION_JSON_VALUE)
    public String receiveVcs(@RequestBody String bodyStr) {
        JSONObject body = new JSONObject(bodyStr);
        Map<String, JSONObject> tppState = stateFor(body.optString("requestId", ""));
        String authzVc = body.optString("authorization_vc", null);
        String delegateVc = body.optString("delegate_vc", null);
        boolean verified = verifyAndStoreIncomingVcs(tppState, authzVc, delegateVc);
        if (!verified) {
            logProtocol("VCs Rejected (Push)", "incoming", "Received VCs rejected due to signature or binding mismatch", null);
            return new JSONObject().put("success", false).put("error", "verification_failed").toString();
        }

        if (body.has("das_encrypted_package")) {
            tppState.put("das_encrypted_package", new JSONObject().put("pkg", body.getString("das_encrypted_package")));
        }

        logProtocol("VCs Received (Push)", "incoming", "Received VCs from Wallet (push mode)", null);

        return new JSONObject().put("success", true).toString();
    }

    // ── State / Status ────────────────────────────────────────
    @GetMapping(value = "/api/state", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getState() {
        return buildStateJson().toString();
    }

    /** Alias for /api/state — used by the frontend */
    @GetMapping(value = "/api/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public String getStatus() {
        return buildStateJson().toString();
    }

    private JSONObject buildStateJson() {
        Map<String, JSONObject> tppState = peekState(null); // current request only (demo UI)
        JSONObject res = new JSONObject();
        boolean hasVcs = tppState.containsKey("authorization_vc") || tppState.containsKey("delegate_vc");
        boolean hasToken = tppState.containsKey("tokenInfo");

        res.put("hasVcs", hasVcs);
        res.put("hasToken", hasToken);

        if (hasToken) {
            JSONObject tokenInfo = tppState.get("tokenInfo");
            res.put("tokenInfo", tokenInfo);
            res.put("grantedScope", tokenInfo.optString("scope", ""));
        }

        if (hasVcs) {
            JSONObject vcs = new JSONObject();

            if (tppState.containsKey("authorization_vc")) {
                JSONObject authVcSdJwt = tppState.get("authorization_vc");
                try {
                    String sdJwt = authVcSdJwt.getString("sdJwt");
                    String[] parts = sdJwt.split("~");
                    List<String> disclosedScopes = new ArrayList<>();
                    List<String> disclosedClaimNames = new ArrayList<>();
                    for (int i = 1; i < parts.length; i++) {
                        if (parts[i].isEmpty()) continue;
                        byte[] decoded = java.util.Base64.getUrlDecoder().decode(parts[i]);
                        JSONArray arr = new JSONArray(new String(decoded, StandardCharsets.UTF_8));
                        if (arr.length() == 3) disclosedClaimNames.add(arr.getString(1));
                        if (arr.length() == 3 && "scopes".equals(arr.getString(1))) {
                            JSONArray scArr = arr.getJSONArray(2);
                            scArr.forEach(s -> disclosedScopes.add(s.toString()));
                        }
                    }
                    vcs.put("authorization", new JSONObject()
                        .put("jti", "authorization-vc")
                        .put("disclosedClaimNames", new JSONArray(disclosedClaimNames))
                        .put("disclosedScopes", new JSONArray(disclosedScopes)));
                } catch (Exception e) {
                    vcs.put("authorization", new JSONObject().put("jti", "authorization-vc"));
                }
            }

            if (tppState.containsKey("delegate_vc")) {
                JSONObject delVcSdJwt = tppState.get("delegate_vc");
                try {
                    String sdJwt = delVcSdJwt.getString("sdJwt");
                    String payloadPart = sdJwt.split("\\.")[1];
                    byte[] payloadBytes = java.util.Base64.getUrlDecoder().decode(payloadPart);
                    JSONObject delPayload = new JSONObject(new String(payloadBytes, StandardCharsets.UTF_8));
                    JSONArray delScopes = delPayload.optJSONArray("delegated_scopes");
                    vcs.put("delegate", new JSONObject()
                        .put("jti", delPayload.optString("jti", "delegate-vc"))
                        .put("delegatedScopes", delScopes != null ? delScopes : new JSONArray()));
                } catch (Exception e) {
                    vcs.put("delegate", new JSONObject().put("jti", "delegate-vc"));
                }
            }

            res.put("vcs", vcs);
        }

        // Delegate request status
        if (tppState.containsKey("delegateRequestId")) {
            res.put("delegateRequestId", tppState.get("delegateRequestId").optString("requestId"));
        }

        res.put("logs", protocolLog);
        return res;
    }

    // ── Token Exchange ────────────────────────────────────────
    @PostMapping(value = {"/api/token", "/api/request-token"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> requestToken(@RequestBody(required = false) String bodyStr) {
        try {
            String tokenRequestId = "";
            if (bodyStr != null && !bodyStr.isBlank()) {
                try { tokenRequestId = new JSONObject(bodyStr).optString("requestId", ""); } catch (Exception ignored) {}
            }
            Map<String, JSONObject> tppState = peekState(tokenRequestId);
            if (!tppState.containsKey("authorization_vc") || !tppState.containsKey("delegate_vc")) {
                return ResponseEntity.badRequest().body(new JSONObject()
                    .put("error", "No VCs available in TPP state. Please request and approve user delegation first.").toString());
            }

            JSONObject vpPayload = new JSONObject();
            vpPayload.put("iss", clientId);

            String audG = bankIssuerUrl + "/token";
            String audR = "http://localhost:4000";
            String rDAS = "";
            if (tppState.containsKey("challengeData")) {
                JSONObject chData = tppState.get("challengeData");
                JSONObject ch = chData.optJSONObject("challenge");
                if (ch != null) {
                    audG = ch.optString("aud_g", audG);
                    audR = ch.optString("aud_r", audR);
                    rDAS = ch.optString("r_das", "");
                }
                vpPayload.put("ch_das", chData.optString("ch_das"));
            }

            vpPayload.put("aud", audG);
            vpPayload.put("aud_r", audR);
            if (!rDAS.isEmpty()) {
                vpPayload.put("r_das", rDAS);
            }

            vpPayload.put("iat", System.currentTimeMillis() / 1000);
            vpPayload.put("exp", System.currentTimeMillis() / 1000 + 300);
            vpPayload.put("jti", UUID.randomUUID().toString());
            String presentedAuthzVc = tppState.get("authorization_vc").getString("sdJwt");
            String presentedDelegateVc = tppState.get("delegate_vc").getString("sdJwt");
            vpPayload.put("authorization_vc", presentedAuthzVc);
            vpPayload.put("delegate_vc", presentedDelegateVc);
            // Commit the assertion to the exact evidence presented and to the challenge being answered (F4).
            vpPayload.put("presentation_binding",
                PresentationBinding.compute(presentedAuthzVc, presentedDelegateVc, rDAS));
            if (tppState.containsKey("das_encrypted_package")) {
                vpPayload.put("das_encrypted_package", tppState.get("das_encrypted_package").getString("pkg"));
            }
            vpPayload.put("tpp_key_id", cryptoService.getEcJwk().getKeyID());

            logProtocol("VP Creation", "internal",
                "Creating Verifiable Presentation JWT with Hybrid signature", null);

            String vpJwt = cryptoService.signHybrid(vpPayload.toString(), "JWT");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.set("X-Forwarded-Host", "localhost:7000");

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            map.add("assertion", vpJwt);

            logProtocol("Token Exchange", "outgoing",
                "Sending VP to Bank Issuer via PQC mTLS", null);

            ResponseEntity<String> response = pqcRestTemplate.getRestTemplate().postForEntity(
                bankIssuerUrl + "/token", new HttpEntity<>(map, headers), String.class);

            JSONObject tokenData = new JSONObject(response.getBody());
            tppState.put("tokenInfo", tokenData);

            logProtocol("Token Received", "incoming",
                "Successfully obtained Access Token", tokenData);

            // Add a token_preview for the UI
            JSONObject uiResponse = new JSONObject(tokenData.toString());
            String accessToken = tokenData.optString("access_token", "");
            if (accessToken.length() > 20) {
                uiResponse.put("token_preview", accessToken.substring(0, 20) + "...");
            }

            return ResponseEntity.ok(uiResponse.toString());
        } catch (org.springframework.web.client.HttpStatusCodeException e) {
            String errBody = e.getResponseBodyAsString();
            if (errBody == null || errBody.trim().isEmpty()) {
                errBody = new JSONObject().put("error", e.getStatusCode().toString()).put("error_description", e.getStatusText()).toString();
            }
            System.err.println("[TPP] Token exchange HTTP error (" + e.getStatusCode() + "): " + errBody);
            return ResponseEntity.status(e.getStatusCode()).body(errBody);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(new JSONObject().put("error", e.getMessage()).toString());
        }
    }

    // ── Banking API ───────────────────────────────────────────

    /** Old endpoint name, kept for compatibility */
    @PostMapping(value = "/api/call-banking", produces = MediaType.APPLICATION_JSON_VALUE)
    public String callBanking() {
        return callBankingWithParams("/api/accounts", "GET");
    }

    /** New endpoint name used by frontend */
    @PostMapping(value = "/api/call-banking-api", produces = MediaType.APPLICATION_JSON_VALUE)
    public String callBankingApi(@RequestBody(required = false) String bodyStr) {
        String endpoint = "/api/accounts";
        String method = "GET";
        String payload = null;
        String requestIdForCall = "";
        if (bodyStr != null && !bodyStr.isEmpty()) {
            try {
                JSONObject body = new JSONObject(bodyStr);
                endpoint = body.optString("endpoint", endpoint);
                method = body.optString("method", method);
                requestIdForCall = body.optString("requestId", "");
                if (body.has("payload")) {
                    payload = body.get("payload").toString();
                }
            } catch (Exception ignored) {}
        }
        return callBankingWithParams(endpoint, method, payload, requestIdForCall);
    }

    private String callBankingWithParams(String endpoint, String httpMethod) {
        return callBankingWithParams(endpoint, httpMethod, null, "");
    }

    private String callBankingWithParams(String endpoint, String httpMethod, String requestPayload, String requestId) {
        try {
            Map<String, JSONObject> tppState = peekState(requestId);
            if (!tppState.containsKey("tokenInfo")) {
                return new JSONObject().put("error", "No Access Token available").toString();
            }
            String token = tppState.get("tokenInfo").getString("access_token");

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.set("X-Forwarded-Host", "localhost:4000");
            if (requestPayload != null && !requestPayload.isEmpty()) {
                headers.setContentType(MediaType.APPLICATION_JSON);
            }

            logProtocol("API Call", "outgoing",
                "Calling Resource Server " + endpoint + " via PQC mTLS", null);

            org.springframework.http.HttpMethod hm = "POST".equalsIgnoreCase(httpMethod)
                ? org.springframework.http.HttpMethod.POST
                : org.springframework.http.HttpMethod.GET;

            HttpEntity<String> entity = (requestPayload != null && !requestPayload.isEmpty())
                ? new HttpEntity<>(requestPayload, headers)
                : new HttpEntity<>(headers);

            ResponseEntity<String> response = pqcRestTemplate.getRestTemplate().exchange(
                resourceServerUrl + endpoint, hm, entity, String.class);

            int statusCode = response.getStatusCode().value();
            Object data;
            try {
                data = new JSONArray(response.getBody());
            } catch (Exception e) {
                try {
                    data = new JSONObject(response.getBody());
                } catch (Exception e2) {
                    data = response.getBody();
                }
            }

            JSONObject res = new JSONObject();
            res.put("success", true);
            res.put("status", statusCode);
            res.put("data", data);
            logProtocol("API Response", "incoming", "Received banking data from " + endpoint, res);
            return res.toString();
        } catch (Exception e) {
            e.printStackTrace();
            JSONObject res = new JSONObject();
            res.put("error", e.getMessage());
            res.put("status", 500);
            return res.toString();
        }
    }

    // ── Reset ─────────────────────────────────────────────────
    @PostMapping(value = "/api/reset", produces = MediaType.APPLICATION_JSON_VALUE)
    public String reset() {
        requestStates.clear();
        requestOrder.clear();
        currentRequestId = null;
        synchronized (protocolLog) {
            protocolLog.clear();
        }
        logProtocol("TPP Reset", "internal", "TPP state and logs cleared", null);
        return new JSONObject().put("success", true).toString();
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
}
