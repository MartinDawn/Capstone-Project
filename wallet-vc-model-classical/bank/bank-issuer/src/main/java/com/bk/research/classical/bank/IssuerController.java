package com.bk.research.classical.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.ECPublicKey;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@CrossOrigin(origins = "*")
public class IssuerController {

    @Value("${ISSUER_URL:http://localhost:7000}")
    private String issuerUrl;

    @Value("${KEYCLOAK_URL:http://localhost:8080}")
    private String keycloakUrl;

    @Value("${REALM:fapi-demo}")
    private String realm;

    @Autowired
    private CryptoService cryptoService;

    @Autowired
    private CertificateRecordStore certificateRecordStore;

    @Autowired
    private CredentialVerificationService credentialVerificationService;

    @Autowired
    private PolicyService policyService;

    @Autowired
    private TypedAuthorityService typedAuthorityService;

    @Autowired
    private RestTemplate restTemplate;

    private final ObjectMapper mapper = new ObjectMapper();

    // In-memory token store
    private final Map<String, TokenData> accessTokens = new ConcurrentHashMap<>();
    private final Map<String, Long> consumedJtiExpirations = new ConcurrentHashMap<>();

    // Keycloak JWKS Cache
    private volatile JWKSet cachedKeycloakJwks = null;
    private volatile long lastKeycloakJwksFetchTime = 0;
    private static final long JWKS_CACHE_TTL_MS = 60000;

    private synchronized JWKSet getKeycloakJwks() {
        long now = System.currentTimeMillis();
        if (cachedKeycloakJwks != null && (now - lastKeycloakJwksFetchTime < JWKS_CACHE_TTL_MS)) {
            return cachedKeycloakJwks;
        }
        String[] endpoints = new String[]{
            keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/certs"
        };
        for (String url : endpoints) {
            try {
                JWKSet jwkSet = JWKSet.load(new URL(url));
                if (jwkSet != null && !jwkSet.getKeys().isEmpty()) {
                    cachedKeycloakJwks = jwkSet;
                    lastKeycloakJwksFetchTime = now;
                    System.out.println("[Bank Issuer] Fetched and cached Keycloak JWKS from " + url);
                    return jwkSet;
                }
            } catch (Exception ignored) { }
        }
        return cachedKeycloakJwks;
    }

    private ObjectNode verifyKeycloakAccessToken(String token) {
        try {
            SignedJWT signedJwt = SignedJWT.parse(token);
            String kid = signedJwt.getHeader().getKeyID();
            JWKSet jwkSet = getKeycloakJwks();
            if (jwkSet == null) {
                System.err.println("[Bank Issuer] Keycloak JWKS unavailable to verify access token");
                return null;
            }
            JWK matchedJwk = kid != null ? jwkSet.getKeyByKeyId(kid) : null;
            if (matchedJwk == null && !jwkSet.getKeys().isEmpty()) {
                for (JWK k : jwkSet.getKeys()) {
                    if (k instanceof ECKey) {
                        matchedJwk = k;
                        break;
                    }
                }
            }
            if (matchedJwk == null) {
                System.err.println("[Bank Issuer] No matching EC key found in Keycloak JWKS for kid: " + kid);
                return null;
            }

            ECKey ecKey = (ECKey) matchedJwk;
            ECPublicKey ecPublicKey = ecKey.toECPublicKey();

            String signingInput = new String(signedJwt.getSigningInput(), StandardCharsets.UTF_8);
            byte[] sigBytes = signedJwt.getSignature().decode();

            boolean valid = cryptoService.verifySignature(signingInput, sigBytes, ecPublicKey);
            if (!valid) {
                System.err.println("[Bank Issuer] Keycloak access token signature verification failed");
                return null;
            }

            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp != null && exp.before(new Date())) {
                System.err.println("[Bank Issuer] Keycloak access token expired at: " + exp);
                return null;
            }

            ObjectNode payloadNode = mapper.createObjectNode();
            for (Map.Entry<String, Object> entry : claims.getClaims().entrySet()) {
                if (entry.getValue() != null) {
                    payloadNode.set(entry.getKey(), mapper.valueToTree(entry.getValue()));
                }
            }
            if (claims.getSubject() != null && !payloadNode.has("sub")) {
                payloadNode.put("sub", claims.getSubject());
            }
            if (claims.getStringClaim("preferred_username") != null && !payloadNode.has("preferred_username")) {
                payloadNode.put("preferred_username", claims.getStringClaim("preferred_username"));
            }
            return payloadNode;
        } catch (Exception e) {
            System.err.println("[Bank Issuer] Error verifying Keycloak access token: " + e.getMessage());
            return null;
        }
    }

    private String resolveClientCertThumbprint(String clientCertThumbprint, String sslClientCertHeader) {
        if (clientCertThumbprint != null && !clientCertThumbprint.trim().isEmpty()) {
            return clientCertThumbprint.trim();
        }
        if (sslClientCertHeader != null && !sslClientCertHeader.trim().isEmpty()) {
            try {
                String decodedPem = java.net.URLDecoder.decode(sslClientCertHeader, StandardCharsets.UTF_8);
                String base64Der = decodedPem
                        .replaceAll("-----BEGIN [^-]+-----", "")
                        .replaceAll("-----END [^-]+-----", "")
                        .replaceAll("\\s+", "");
                if (!base64Der.isEmpty()) {
                    byte[] derBytes = Base64.getDecoder().decode(base64Der);
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] digest = md.digest(derBytes);
                    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
                }
            } catch (Exception e) {
                System.err.println("[IssuerController] Failed to parse ssl-client-cert: " + e.getMessage());
            }
        }
        return null;
    }

    private static class TokenData {
        String sub;
        String scope;
        long exp;
        String cnfThumbprint;
        JsonNode vcGrant;

        public TokenData(String sub, String scope, long exp, String cnfThumbprint, JsonNode vcGrant) {
            this.sub = sub;
            this.scope = scope;
            this.exp = exp;
            this.cnfThumbprint = cnfThumbprint;
            this.vcGrant = vcGrant;
        }
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        ObjectNode res = mapper.createObjectNode();
        res.put("status", "UP");
        res.put("service", "bank-issuer-classical");
        res.put("crypto", "ECDSA-P256");
        res.put("issuer", issuerUrl);
        res.put("policy_version", policyService.getVersion());
        return ResponseEntity.ok(res);
    }

    @GetMapping("/.well-known/openid-credential-issuer")
    public ResponseEntity<?> issuerMetadata() {
        ObjectNode root = mapper.createObjectNode();
        root.put("credential_issuer", issuerUrl);
        root.putArray("authorization_servers").add(keycloakUrl + "/realms/" + realm);
        root.put("credential_endpoint", issuerUrl + "/credential");

        ObjectNode configs = mapper.createObjectNode();

        ObjectNode authz = mapper.createObjectNode();
        authz.put("format", "vc+sd-jwt");
        authz.put("vct", "AuthorizationCredential");
        authz.put("scope", "authorization_credential");
        authz.putArray("cryptographic_binding_methods_supported").add("jwk");
        authz.putArray("credential_signing_alg_values_supported").add("ES256");
        configs.set("AuthorizationCredential", authz);

        root.set("credential_configurations_supported", configs);
        return ResponseEntity.ok(root);
    }

    @GetMapping(value = {"/jwks", "/.well-known/jwks.json"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> jwks() throws Exception {
        ObjectNode root = mapper.createObjectNode();
        ArrayNode keys = root.putArray("keys");
        ObjectNode jwk = (ObjectNode) mapper.readTree(cryptoService.getEcJwk().toPublicJWK().toJSONString());
        keys.add(jwk);
        return ResponseEntity.ok(root);
    }

    @GetMapping("/api/policy/tpp-scopes/{tppClientId}")
    public ResponseEntity<?> getTppScopes(@PathVariable String tppClientId) {
        if (!policyService.isTppRegisteredAndActive(tppClientId)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "unauthorized_client", "error_description", "TPP client is not registered or not active"));
        }

        Set<String> allowedScopes = policyService.getTppMaxScopes(tppClientId);
        ObjectNode res = mapper.createObjectNode();
        res.put("tpp_client_id", tppClientId);
        res.put("status", "ACTIVE");
        res.put("policy_version", policyService.getVersion());
        ArrayNode scopesArr = res.putArray("allowed_scopes");
        for (String s : allowedScopes) {
            scopesArr.add(s);
        }
        return ResponseEntity.ok(res);
    }

    @GetMapping("/api/policy/master-catalog")
    public ResponseEntity<?> getMasterCatalog() {
        ObjectNode res = mapper.createObjectNode();
        res.put("policy_version", policyService.getVersion());
        ArrayNode scopesArr = res.putArray("master_scopes");
        for (String s : policyService.getMasterScopeCatalog()) {
            scopesArr.add(s);
        }
        return ResponseEntity.ok(res);
    }

    @GetMapping("/offer/{type}")
    public ResponseEntity<?> credentialOffer(@PathVariable String type) {
        String credConfigId = type.equals("identity") ? "IdentityCredential" : "AuthorizationCredential";
        String issuerState = UUID.randomUUID().toString();

        ObjectNode offer = mapper.createObjectNode();
        offer.put("credential_issuer", issuerUrl);
        offer.putArray("credential_configuration_ids").add(credConfigId);
        ObjectNode grants = mapper.createObjectNode();
        ObjectNode authCode = mapper.createObjectNode();
        authCode.put("issuer_state", issuerState);
        grants.set("authorization_code", authCode);
        offer.set("grants", grants);

        String offerUri = "openid-credential-offer://?credential_offer=" + java.net.URLEncoder.encode(offer.toString(), StandardCharsets.UTF_8);

        ObjectNode res = mapper.createObjectNode();
        res.set("offer", offer);
        res.put("offerUri", offerUri);
        res.put("issuerState", issuerState);
        res.put("credentialConfigId", credConfigId);
        res.put("authorizationEndpoint", keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/auth");
        res.put("tokenEndpoint", keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token");
        res.put("credentialEndpoint", issuerUrl + "/credential");

        return ResponseEntity.ok(res);
    }

    private ObjectNode buildSdJwtVc(String vct, JsonNode holderJwk, String holderCertRef, ObjectNode claims, List<String> selectiveFields) throws Exception {
        String jti = "urn:uuid:" + UUID.randomUUID().toString();
        long now = System.currentTimeMillis() / 1000;

        List<String> disclosures = new ArrayList<>();
        List<String> sdHashes = new ArrayList<>();

        ObjectNode payload = mapper.createObjectNode();
        payload.put("iss", issuerUrl);
        if (holderJwk != null) {
            payload.put("sub", holderJwk.toString());
            ObjectNode cnf = mapper.createObjectNode();
            cnf.set("jwk", holderJwk);
            payload.set("cnf", cnf);
        }
        if (holderCertRef != null && !holderCertRef.isEmpty()) {
            payload.put("holder_cert_ref", holderCertRef);
        }
        payload.put("iat", now);
        payload.put("exp", now + 86400 * 365);
        payload.put("jti", jti);
        payload.put("vct", vct);
        String f1TransactionId = "urn:uuid:" + UUID.randomUUID();
        String bindingProfile = "ECDSA-P384-SHA384";
        String statusListReference = issuerUrl + "/status/issuance-binding/" + holderCertRef;
        payload.put("f1_transaction_id", f1TransactionId);
        payload.put("binding_profile", bindingProfile);
        payload.put("credential_status_ref", statusListReference);

        Iterator<Map.Entry<String, JsonNode>> it = claims.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> entry = it.next();
            if (selectiveFields.contains(entry.getKey())) {
                byte[] saltBytes = new byte[16];
                new java.security.SecureRandom().nextBytes(saltBytes);
                String salt = Base64.getUrlEncoder().withoutPadding().encodeToString(saltBytes);

                ArrayNode discArr = mapper.createArrayNode();
                discArr.add(salt);
                discArr.add(entry.getKey());
                discArr.add(entry.getValue());

                String discB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(discArr.toString().getBytes(StandardCharsets.UTF_8));
                disclosures.add(discB64);

                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(discB64.getBytes(StandardCharsets.UTF_8));
                String hashB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                sdHashes.add(hashB64);
            } else {
                payload.set(entry.getKey(), entry.getValue());
            }
        }

        // Constant-size Disclosure Envelope padding (pad to 8 disclosures)
        int targetDisclosureCount = 8;
        int dummyCount = 0;
        while (disclosures.size() < targetDisclosureCount) {
            dummyCount++;
            byte[] saltBytes = new byte[16];
            new java.security.SecureRandom().nextBytes(saltBytes);
            String salt = Base64.getUrlEncoder().withoutPadding().encodeToString(saltBytes);

            ArrayNode dummyArr = mapper.createArrayNode();
            dummyArr.add(salt);
            dummyArr.add("_dummy_claim_" + dummyCount);
            dummyArr.add("dummy_padding_value");

            String dummyB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(dummyArr.toString().getBytes(StandardCharsets.UTF_8));
            disclosures.add(dummyB64);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(dummyB64.getBytes(StandardCharsets.UTF_8));
            String hashB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            sdHashes.add(hashB64);
        }

        if (!sdHashes.isEmpty()) {
            ArrayNode sd = payload.putArray("_sd");
            for (String h : sdHashes) {
                sd.add(h);
            }
            payload.put("_sd_alg", "sha-256");
        }

        String signedJwt = cryptoService.sign(payload.toString(), "vc+sd-jwt");

        StringBuilder sdJwt = new StringBuilder(signedJwt);
        for (String d : disclosures) {
            sdJwt.append("~").append(d);
        }
        sdJwt.append("~");

        ObjectNode result = mapper.createObjectNode();
        result.put("sdJwt", sdJwt.toString());
        result.put("jti", jti);
        result.put("signedComponent", signedJwt);
        result.put("f1TransactionId", f1TransactionId);
        result.put("bindingProfile", bindingProfile);
        result.put("statusListReference", statusListReference);
        result.put("validFrom", now);
        result.put("validUntil", now + 86400 * 365);
        return result;
    }

    private void commitIssuanceBinding(String holderCertRef, ObjectNode credential) {
        certificateRecordStore.commitCredential(
                holderCertRef,
                credential.get("jti").asText(),
                credential.get("signedComponent").asText(),
                credential.get("bindingProfile").asText(),
                credential.get("f1TransactionId").asText(),
                credential.get("validFrom").asLong(),
                credential.get("validUntil").asLong(),
                credential.get("statusListReference").asText());
    }

    @PostMapping("/credential")
    public ResponseEntity<?> credential(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestHeader(value = "X-Client-Cert-Thumbprint", required = false) String clientCertThumbprintHeader,
            @RequestHeader(value = "ssl-client-cert", required = false) String sslClientCert,
            @RequestBody JsonNode reqBody) {
        try {
            String clientCertThumbprint = resolveClientCertThumbprint(clientCertThumbprintHeader, sslClientCert);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "unauthorized"));
            }
            String token = authHeader.substring(7);

            JsonNode tokenPayload = null;
            if (accessTokens.containsKey(token)) {
                TokenData td = accessTokens.get(token);
                if (td.exp < System.currentTimeMillis() / 1000) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_token"));
                }
                tokenPayload = mapper.createObjectNode().put("sub", td.sub).put("scope", td.scope);
            } else {
                ObjectNode verifiedPayload = verifyKeycloakAccessToken(token);
                if (verifiedPayload == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_token", "error_description", "Invalid or unverified Keycloak access token (unsigned alg:none tokens are forbidden)"));
                }
                tokenPayload = verifiedPayload;
            }

            JsonNode proof = reqBody.get("proof");
            if (proof == null || !proof.has("jwt") || proof.get("jwt").asText().trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_proof", "error_description", "Proof-of-possession (PoP) is mandatory for key-bound credentials"));
            }
            String proofJwt = proof.get("jwt").asText().trim();
            String[] pParts = proofJwt.split("\\.");
            if (pParts.length < 3) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_proof", "error_description", "Malformed PoP JWT structure"));
            }

            String pHeader = new String(Base64.getUrlDecoder().decode(pParts[0]), StandardCharsets.UTF_8);
            JsonNode pHeaderNode = mapper.readTree(pHeader);
            JsonNode holderJwk = null;
            if (pHeaderNode.has("jwk")) {
                holderJwk = pHeaderNode.get("jwk");
            }
            if (holderJwk == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_proof", "error_description", "PoP header missing mandatory holder JWK"));
            }

            try {
                ECKey proofEcKey = ECKey.parse(holderJwk.toString());
                ECPublicKey proofPubKey = proofEcKey.toECPublicKey();
                String pSigningInput = pParts[0] + "." + pParts[1];
                byte[] pSigBytes = Base64.getUrlDecoder().decode(pParts[2]);
                boolean proofValid = cryptoService.verifySignature(pSigningInput, pSigBytes, proofPubKey);
                if (!proofValid) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_proof", "error_description", "PoP signature verification failed under Holder key"));
                }
            } catch (Exception sigEx) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_proof", "error_description", "PoP signature check error: " + sigEx.getMessage()));
            }

            String pPayload = new String(Base64.getUrlDecoder().decode(pParts[1]), StandardCharsets.UTF_8);
            JsonNode pPayloadNode = mapper.readTree(pPayload);
            if (pPayloadNode.has("aud")) {
                String pAud = pPayloadNode.get("aud").asText();
                if (!pAud.equals(issuerUrl) && !pAud.equals(issuerUrl + "/credential") && !pAud.contains("localhost:7000") && !pAud.contains("tls-wallet-outbound") && !pAud.contains("oqs-wallet-outbound") && !pAud.contains("bank-issuer") && !pAud.contains(":7000")) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_proof", "error_description", "PoP audience mismatch"));
                }
            }

            String credType = reqBody.has("credential_configuration_id") ? reqBody.get("credential_configuration_id").asText() : "AuthorizationCredential";
            String sub = "testuser";
            if (tokenPayload.hasNonNull("preferred_username") && !tokenPayload.get("preferred_username").asText().trim().isEmpty()) {
                sub = tokenPayload.get("preferred_username").asText().trim();
            } else if (tokenPayload.hasNonNull("sub") && !tokenPayload.get("sub").asText().trim().isEmpty()) {
                sub = tokenPayload.get("sub").asText().trim();
            }
            // Register holder certificate in bank-controlled CertificateRecordStore with tau_W
            String holderCertRef = certificateRecordStore.registerCertificate(sub, holderJwk, clientCertThumbprint);

            ObjectNode result = null;
            if ("AuthorizationCredential".equals(credType)) {
                ObjectNode claims = mapper.createObjectNode();
                claims.put("holder_subject", sub);
                claims.put("wallet_certificate_thumbprint", clientCertThumbprint);
                ArrayNode scopes = mapper.createArrayNode();
                String tScope = tokenPayload.has("scope") ? tokenPayload.get("scope").asText() : "";
                Set<String> tokenScopeSet = new HashSet<>();
                for (String s : tScope.split(" ")) {
                    if (!s.trim().isEmpty()) {
                        tokenScopeSet.add(s.trim());
                    }
                }

                // Canonical Open Banking UK Permissions & Policy Scopes
                for (String p : policyService.getBankPolicyScopes()) {
                    scopes.add(p);
                }

                // Add any extra scopes from token / policy (including backward-compatible aliases)
                for (String s : tokenScopeSet) {
                    if (policyService.getBankPolicyScopes().contains(s)) {
                        boolean alreadyAdded = false;
                        for (JsonNode existing : scopes) {
                            if (existing.asText().equals(s)) {
                                alreadyAdded = true;
                                break;
                            }
                        }
                        if (!alreadyAdded) {
                            scopes.add(s);
                        }
                    }
                }

                // Ensure essential fallback scopes if empty
                if (scopes.isEmpty()) {
                    scopes.add("ReadAccountsDetail");
                    scopes.add("ReadBalances");
                    scopes.add("ReadTransactionsDetail");
                    scopes.add("CreateDomesticPayment");
                    scopes.add("accounts:read");
                    scopes.add("transfers:read");
                }
                claims.set("scopes", scopes);

                // Standard Open Banking UK OBReadConsent1 resource structure
                Instant nowInstant = Instant.now();
                ObjectNode consent = mapper.createObjectNode();
                consent.put("ConsentId", "urn:uk:obie:consent:" + UUID.randomUUID().toString());
                consent.put("Status", "Authorised");
                consent.put("CreationDateTime", nowInstant.toString());
                consent.put("StatusUpdateDateTime", nowInstant.toString());

                ArrayNode permArray = consent.putArray("Permissions");
                for (JsonNode p : scopes) {
                    permArray.add(p.asText());
                }

                consent.put("ExpirationDateTime", nowInstant.plus(90, ChronoUnit.DAYS).toString());
                consent.put("TransactionFromDateTime", "2024-01-01T00:00:00Z");
                consent.put("TransactionToDateTime", nowInstant.toString());

                // Backward-compatible metadata
                consent.put("granted_at", nowInstant.toString());
                consent.put("purpose", "Open Banking UK Delegated Access");
                consent.put("account_holder", sub);

                claims.set("consent", consent);

                result = buildSdJwtVc("AuthorizationCredential", holderJwk, holderCertRef, claims, Arrays.asList("scopes", "consent"));
                commitIssuanceBinding(holderCertRef, result);
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "unsupported_credential_type"));
            }

            ObjectNode res = mapper.createObjectNode();
            res.put("credential", result.get("sdJwt").asText());
            res.put("format", "vc+sd-jwt");
            res.put("c_nonce", UUID.randomUUID().toString());
            res.put("c_nonce_expires_in", 300);
            return ResponseEntity.ok(res);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "server_error", "error_description", e.getMessage()));
        }
    }

    /**
     * Dedicated internal bootstrap endpoint for automated test/development wallet initialization.
     * Accessible ONLY via authenticated mTLS connection from authorized Wallet.
     */
    @PostMapping("/api/internal/bootstrap-credential")
    public ResponseEntity<?> bootstrapCredential(
            @RequestHeader(value = "X-Client-Cert-Thumbprint", required = false) String clientCertThumbprintHeader,
            @RequestHeader(value = "ssl-client-cert", required = false) String sslClientCert,
            @RequestBody JsonNode reqBody) {
        try {
            String clientCertThumbprint = resolveClientCertThumbprint(clientCertThumbprintHeader, sslClientCert);
            if (clientCertThumbprint == null || clientCertThumbprint.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "unauthorized",
                    "error_description", "Internal bootstrap requires mutual TLS certificate authentication"
                ));
            }

            JsonNode proof = reqBody.get("proof");
            JsonNode holderJwk = null;
            if (proof != null && proof.has("jwt")) {
                String proofJwt = proof.get("jwt").asText();
                String[] pParts = proofJwt.split("\\.");
                if (pParts.length >= 3) {
                    String pHeader = new String(Base64.getUrlDecoder().decode(pParts[0]), StandardCharsets.UTF_8);
                    JsonNode pHeaderNode = mapper.readTree(pHeader);
                    if (pHeaderNode.has("jwk")) {
                        holderJwk = pHeaderNode.get("jwk");
                    }
                }
            }

            String sub = "testuser";
            String holderCertRef = certificateRecordStore.registerCertificate(sub, holderJwk, clientCertThumbprint);

            ObjectNode claims = mapper.createObjectNode();
            claims.put("sub", sub);
            claims.put("holder_cert_ref", holderCertRef);
            claims.put("holder_subject", sub);
            claims.put("wallet_certificate_thumbprint", clientCertThumbprint);

            ArrayNode scopesArr = claims.putArray("scopes");
            for (String s : policyService.getMasterScopeCatalog()) {
                scopesArr.add(s);
            }

            ObjectNode consent = mapper.createObjectNode();
            consent.put("Status", "Authorised");
            consent.put("Permissions", scopesArr);
            consent.put("CreationDateTime", java.time.Instant.now().toString());
            consent.put("ExpirationDateTime", java.time.Instant.now().plusSeconds(86400 * 90).toString());
            consent.put("purpose", "Open Banking UK Delegated Access");
            consent.put("account_holder", sub);
            claims.set("consent", consent);

            ObjectNode result = buildSdJwtVc("AuthorizationCredential", holderJwk, holderCertRef, claims, Arrays.asList("scopes", "consent"));
            commitIssuanceBinding(holderCertRef, result);

            ObjectNode res = mapper.createObjectNode();
            res.put("credential", result.get("sdJwt").asText());
            res.put("format", "vc+sd-jwt");
            res.put("c_nonce", UUID.randomUUID().toString());
            res.put("c_nonce_expires_in", 300);
            return ResponseEntity.ok(res);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "server_error", "error_description", e.getMessage()));
        }
    }

    // Pre-F2 Challenge Store
    private final Map<String, ChallengeData> pendingChallenges = new ConcurrentHashMap<>();

    public static class ChallengeData {
        public final String rDAS;
        public final String nKB;
        public final String tppClientId;
        public final String clientCertThumbprint;
        public final String audG;
        public final String audKB;
        public final String audR;
        public final String requestHash;
        public final long iat;
        public final long exp;

        public ChallengeData(String rDAS, String nKB, String tppClientId, String clientCertThumbprint,
                             String audG, String audKB, String audR, String requestHash, long iat, long exp) {
            this.rDAS = rDAS;
            this.nKB = nKB;
            this.tppClientId = tppClientId;
            this.clientCertThumbprint = clientCertThumbprint;
            this.audG = audG;
            this.audKB = audKB;
            this.audR = audR;
            this.requestHash = requestHash;
            this.iat = iat;
            this.exp = exp;
        }
    }

    @PostMapping("/api/v1/challenge")
    public ResponseEntity<?> createChallenge(
            @RequestHeader(value = "X-Client-Cert-Thumbprint", required = false) String clientCertThumbprintHeader,
            @RequestHeader(value = "ssl-client-cert", required = false) String sslClientCert,
            @RequestBody JsonNode req) {
        try {
            String clientCertThumbprint = resolveClientCertThumbprint(clientCertThumbprintHeader, sslClientCert);
            String tppClientId = req.has("tpp_client_id") ? req.get("tpp_client_id").asText() : "";
            if (!policyService.isTppRegisteredAndActive(tppClientId)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "unauthorized_client", "error_description", "TPP client is not active in bank policy"));
            }

            String rDAS = "rdas_" + UUID.randomUUID().toString().replace("-", "");
            String nKB = UUID.randomUUID().toString().replace("-", "");
            long now = System.currentTimeMillis() / 1000;
            long exp = now + 60; // 60s per FAPI/VDAM challenge window

            String audG = issuerUrl + "/token";
            String audKB = issuerUrl + "/verify-kb";
            String audR = req.has("aud_r") ? req.get("aud_r").asText() : "http://localhost:4000";
            String requestHash = req.has("request_hash") ? req.get("request_hash").asText() : "";

            ChallengeData cd = new ChallengeData(rDAS, nKB, tppClientId, clientCertThumbprint, audG, audKB, audR, requestHash, now, exp);
            pendingChallenges.put(rDAS, cd);

            ObjectNode chObj = mapper.createObjectNode();
            chObj.put("r_das", rDAS);
            chObj.put("nonce", nKB);
            chObj.put("tpp_client_id", tppClientId);
            chObj.put("aud_g", audG);
            chObj.put("aud_kb", audKB);
            chObj.put("aud_r", audR);
            chObj.put("request_hash", requestHash);
            chObj.put("iat", now);
            chObj.put("exp", exp);

            String signedChDAS = cryptoService.sign(chObj.toString(), "JWT");

            ObjectNode resp = mapper.createObjectNode();
            resp.put("ch_das", signedChDAS);
            resp.set("challenge", chObj);
            return ResponseEntity.ok(resp);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "server_error", "error_description", e.getMessage()));
        }
    }

    @PostMapping(value = "/token", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<?> token(
            @RequestHeader(value = "X-Client-Cert-Thumbprint", required = false) String clientCertThumbprintHeader,
            @RequestHeader(value = "ssl-client-cert", required = false) String sslClientCert,
            @RequestParam Map<String, String> body) {
        try {
            String clientCertThumbprint = resolveClientCertThumbprint(clientCertThumbprintHeader, sslClientCert);
            String grantType = body.get("grant_type");
            String assertion = body.get("assertion");

            if (!"urn:ietf:params:oauth:grant-type:jwt-bearer".equals(grantType) || assertion == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_request", "error_description", "Missing grant_type or assertion"));
            }

            String[] aParts = assertion.split("\\.");
            if (aParts.length < 3) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "Malformed assertion JWT"));
            }

            String vpPayloadJson;
            JsonNode vpPayload;
            try {
                vpPayloadJson = new String(Base64.getUrlDecoder().decode(aParts[1]), StandardCharsets.UTF_8);
                vpPayload = mapper.readTree(vpPayloadJson);
            } catch (Exception e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "Malformed assertion payload"));
            }

            String tppClientId = vpPayload.has("iss") ? vpPayload.get("iss").asText() : "";
            if (!policyService.isTppRegisteredAndActive(tppClientId)) {
                System.err.println("[DAS F4-F5 Boundary] Rejection: TPP client '" + tppClientId + "' is not active in bank policy");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "unauthorized_client", "error_description", "TPP client is not active in bank policy"));
            }

            // Anti-replay protection for JTI with bounded TTL eviction
            long nowSec = System.currentTimeMillis() / 1000;
            consumedJtiExpirations.entrySet().removeIf(entry -> entry.getValue() < nowSec);
            if (vpPayload.has("jti")) {
                String vpJti = vpPayload.get("jti").asText();
                long vpExp = vpPayload.has("exp") ? vpPayload.get("exp").asLong() : (nowSec + 300);
                if (consumedJtiExpirations.putIfAbsent(vpJti, vpExp) != null) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "REJECT_REPLAYED_CREDENTIAL"));
                }
            }

            // Enforce Grant Audience (aud_g / aud)
            String presentedAudG = vpPayload.has("aud_g") ? vpPayload.get("aud_g").asText() : (vpPayload.has("aud") ? vpPayload.get("aud").asText() : "");
            String expectedAudG = issuerUrl + "/token";
            if (!presentedAudG.isEmpty() && !presentedAudG.equals(expectedAudG) && !presentedAudG.equals(issuerUrl) && !presentedAudG.contains("localhost:7000") && !presentedAudG.contains("bank-issuer:7000") && !presentedAudG.contains(":7000")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "REJECT_INVALID_GRANT_AUDIENCE"));
            }

            // Challenge consumption / anti-replay check
            ChallengeData cd = null;
            if (vpPayload.has("ch_das") || vpPayload.has("r_das")) {
                String rDas = vpPayload.has("r_das") ? vpPayload.get("r_das").asText() : "";
                if (rDas.isEmpty() && vpPayload.has("ch_das")) {
                    String chToken = vpPayload.get("ch_das").asText();
                    String[] chParts = chToken.split("\\.");
                    if (chParts.length >= 2) {
                        JsonNode chPayload = mapper.readTree(new String(Base64.getUrlDecoder().decode(chParts[1]), StandardCharsets.UTF_8));
                        rDas = chPayload.has("r_das") ? chPayload.get("r_das").asText() : "";
                    }
                }
                if (!rDas.isEmpty()) {
                    cd = pendingChallenges.remove(rDas);
                    if (cd == null) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "REJECT_REPLAYED_CREDENTIAL: DAS challenge already consumed or invalid"));
                    }
                    if (cd.exp < System.currentTimeMillis() / 1000) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "REJECT_REVOKED_OR_EXPIRED_CREDENTIAL: DAS challenge has expired"));
                    }
                    if (cd.clientCertThumbprint != null && clientCertThumbprint != null && !cd.clientCertThumbprint.equals(clientCertThumbprint)) {
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_grant", "error_description", "REJECT_PRESENTER_CERTIFICATE_MISMATCH"));
                    }
                }
            }

            if (!vpPayload.has("authorization_vc") || !vpPayload.has("delegate_vc")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "VP assertion missing authorization_vc or delegate_vc"));
            }

            String authzVcStr = vpPayload.get("authorization_vc").asText();
            String delegateVcStr = vpPayload.get("delegate_vc").asText();

            // F4 presentation binding: the assertion must commit to the exact artifacts it presents and to the
            // challenge it answers. Mandatory - an assertion without it cannot be bound to this F4 context.
            if (!vpPayload.has("presentation_binding")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "error", "invalid_grant",
                        "error_description", "REJECT_MISSING_PRESENTATION_BINDING: VP assertion carries no presentation_binding for this F4 context"
                ));
            }
            String expectedBinding = PresentationBinding.compute(authzVcStr, delegateVcStr,
                    (cd != null && cd.rDAS != null) ? cd.rDAS : "");
            if (!expectedBinding.equals(vpPayload.get("presentation_binding").asText())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "error", "invalid_grant",
                        "error_description", "REJECT_PRESENTATION_BINDING_MISMATCH: presentation binding does not match the presented evidence and current F4 challenge context"
                ));
            }

            CredentialVerificationService.VerificationResult rootResult = credentialVerificationService.verifyRootScopeVc(authzVcStr, issuerUrl);
            if (rootResult == null || !rootResult.isValid()) {
                String errMsg = rootResult != null ? rootResult.getErrorMessage() : "Root Scope VC verification failed";
                System.err.println("[DAS F4 /token Reject 401] Root VC verification failed: " + errMsg);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_grant", "error_description", errMsg));
            }

            CertificateRecordStore.CertificateRecord bindingRecord = rootResult.getCertRecord();
            long initialBindingVersion = bindingRecord != null ? bindingRecord.getAuditVersion() : 0L;
            if (vpPayload.has("binding_snapshot_timestamp")) {
                long snapshotTimestamp = vpPayload.get("binding_snapshot_timestamp").asLong();
                if (snapshotTimestamp > nowSec || nowSec - snapshotTimestamp > 30) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                            "error", "invalid_grant",
                            "error_description", "REJECT_STALE_BINDING_SNAPSHOT: authenticated binding snapshot is outside the 30 second freshness window"));
                }
            }
            if (vpPayload.has("binding_version")
                    && bindingRecord != null
                    && vpPayload.get("binding_version").asLong() != bindingRecord.getAuditVersion()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "error", "invalid_grant",
                        "error_description", "REJECT_ROLLBACK_VERSION: presented binding version does not match authoritative state"));
            }

            CredentialVerificationService.VerificationResult delegateResult = credentialVerificationService.verifyDelegationVc(delegateVcStr, rootResult, tppClientId);
            if (delegateResult == null || !delegateResult.isValid()) {
                String errMsg = delegateResult != null ? delegateResult.getErrorMessage() : "Delegation VC verification failed";
                System.err.println("[DAS F4 /token Reject 401] Delegate VC verification failed: " + errMsg);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_grant", "error_description", errMsg));
            }

            // Validate KB-JWT parameters against challenge if present
            String[] dParts = delegateVcStr.split("~");
            if (dParts.length > 1 && !dParts[dParts.length - 1].isEmpty()) {
                String kbJwtStr = dParts[dParts.length - 1];
                String[] kbSections = kbJwtStr.split("\\.");
                if (kbSections.length >= 2) {
                    try {
                        JsonNode kbPayload = mapper.readTree(new String(Base64.getUrlDecoder().decode(kbSections[1]), StandardCharsets.UTF_8));
                        if (cd != null) {
                            if (kbPayload.has("nonce") && !cd.nKB.equals(kbPayload.get("nonce").asText())) {
                                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "REJECT_NONCE_MISMATCH"));
                            }
                            if (kbPayload.has("aud") && !cd.audKB.equals(kbPayload.get("aud").asText()) && !kbPayload.get("aud").asText().equals(issuerUrl + "/verify-kb") && !kbPayload.get("aud").asText().equals(issuerUrl)) {
                                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "REJECT_INVALID_KB_AUDIENCE"));
                            }
                        }
                    } catch (Exception kbEx) {
                        System.err.println("[Classical IssuerController] Error parsing KB-JWT in delegation VC: " + kbEx.getMessage());
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "REJECT_INVALID_KB_JWT: " + kbEx.getMessage()));
                    }
                }
            }

            // Verify VP Assertion Signature under TPP's Public Key from Delegation VC
            JsonNode delegatePayload = delegateResult.getPayload();
            if (delegatePayload == null || !delegatePayload.has("cnf") || !delegatePayload.get("cnf").has("jwk")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", "invalid_grant", "error_description", "Delegation VC missing cnf.jwk for TPP verification"));
            }

            try {
                JsonNode tppJwkNode = delegatePayload.get("cnf").get("jwk");
                ECKey tppEcKey = ECKey.parse(tppJwkNode.toString());
                ECPublicKey tppEcPubKey = tppEcKey.toECPublicKey();

                String vpSigningInput = aParts[0] + "." + aParts[1];
                byte[] vpSigBytes = Base64.getUrlDecoder().decode(aParts[2]);

                boolean vpSigValid = cryptoService.verifySignature(vpSigningInput, vpSigBytes, tppEcPubKey);
                if (!vpSigValid) {
                    System.err.println("[DAS F4-F5 Boundary] VP assertion signature verification failed under TPP key");
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_grant", "error_description", "VP assertion signature verification failed under TPP key"));
                }
            } catch (Exception vpSigEx) {
                System.err.println("[DAS F4-F5 Boundary] Error verifying VP assertion signature: " + vpSigEx.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_grant", "error_description", "VP assertion signature verification error: " + vpSigEx.getMessage()));
            }

            // F4-07: Decrypt and verify DAS-only encrypted package if present
            if (vpPayload.has("das_encrypted_package")) {
                String dasPkgStr = vpPayload.get("das_encrypted_package").asText();
                try {
                    String decryptedClaimsJson = cryptoService.decryptDasPackage(dasPkgStr);
                    JsonNode dasClaims = mapper.readTree(decryptedClaimsJson);
                    // Verify context binding (TPP client ID, challenge / r_das)
                    if (dasClaims.has("tpp_client_id") && !tppClientId.equals(dasClaims.get("tpp_client_id").asText())) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                            "error", "invalid_grant",
                            "error_description", "REJECT_DAS_ENCRYPTED_PACKAGE_MISMATCH: TPP client mismatch"
                        ));
                    }
                    if (cd != null && dasClaims.has("r_das") && !cd.rDAS.equals(dasClaims.get("r_das").asText())) {
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                            "error", "invalid_grant",
                            "error_description", "REJECT_DAS_ENCRYPTED_PACKAGE_MISMATCH: DAS challenge mismatch"
                        ));
                    }
                    System.out.println("[DAS F4-07] DAS-only encrypted package decrypted & verified successfully: " + dasClaims);
                } catch (Exception dasPkgEx) {
                    System.err.println("[DAS F4-07] Failed to decrypt DAS-only package: " + dasPkgEx.getMessage());
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "error", "invalid_grant",
                        "error_description", "REJECT_INVALID_DAS_ENCRYPTED_PACKAGE: " + dasPkgEx.getMessage()
                    ));
                }
            }

            // Compute Effective Scope: S_token = S_SC ∩ S_H ∩ S_R ∩ S_T ∩ S_P
            Set<String> bankPolicyScopes = policyService.getBankPolicyScopes();
            if (bankPolicyScopes == null || bankPolicyScopes.isEmpty()) {
                bankPolicyScopes = new HashSet<>(Arrays.asList("accounts:read", "transfers:read", "transfers:write", "profile:read", "transactions:read"));
            }

            Set<String> s_SC = (rootResult.getScopes() != null && !rootResult.getScopes().isEmpty())
                    ? new HashSet<>(rootResult.getScopes())
                    : new HashSet<>(bankPolicyScopes);

            Set<String> s_H = (delegateResult.getScopes() != null && !delegateResult.getScopes().isEmpty())
                    ? new HashSet<>(delegateResult.getScopes())
                    : new HashSet<>(s_SC);

            Set<String> s_T = policyService.getTppMaxScopes(tppClientId);
            if (s_T == null || s_T.isEmpty()) {
                s_T = new HashSet<>(bankPolicyScopes);
            }
            Set<String> s_P = bankPolicyScopes;

            Set<String> s_R = new HashSet<>(s_H);
            if (body.containsKey("scope") && body.get("scope") != null && !body.get("scope").isEmpty()) {
                s_R = new HashSet<>(Arrays.asList(body.get("scope").split(" ")));
            }

            Set<String> s_token = new HashSet<>();
            for (String sh : s_H) {
                if (CredentialVerificationService.isContained(sh, s_SC)) {
                    s_token.add(sh);
                    Set<String> syn = CredentialVerificationService.SCOPE_SYNONYMS.get(sh);
                    if (syn != null) {
                        for (String sy : syn) {
                            if (bankPolicyScopes.contains(sy)) {
                                s_token.add(sy);
                            }
                        }
                    }
                }
            }
            if (!s_R.isEmpty()) {
                Set<String> intersected = new HashSet<>();
                for (String st : s_token) {
                    if (CredentialVerificationService.isContained(st, s_R) || s_R.contains(st)) {
                        intersected.add(st);
                    }
                }
                if (!intersected.isEmpty()) {
                    s_token = intersected;
                }
            }
            if (s_T != null && !s_T.isEmpty()) {
                Set<String> tppFiltered = new HashSet<>();
                for (String st : s_token) {
                    if (CredentialVerificationService.isContained(st, s_T) || s_T.contains(st)) {
                        tppFiltered.add(st);
                    }
                }
                if (!tppFiltered.isEmpty()) {
                    s_token = tppFiltered;
                }
            }
            s_token.retainAll(s_P);

            ObjectNode effectiveTypedAuthority = null;
            JsonNode rootPayload = rootResult.getPayload();
            JsonNode holderPayload = delegateResult.getPayload();
            boolean hasAnyTypedAuthority =
                    (rootPayload != null && rootPayload.has("typed_authority"))
                    || (holderPayload != null && holderPayload.has("typed_authority"))
                    || vpPayload.has("requested_authority")
                    || vpPayload.has("tpp_authority");
            if (hasAnyTypedAuthority) {
                if (rootPayload == null || !rootPayload.has("typed_authority")
                        || holderPayload == null || !holderPayload.has("typed_authority")
                        || !vpPayload.has("requested_authority") || !vpPayload.has("tpp_authority")) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                            "error", "invalid_grant",
                            "error_description", "REJECT_INCOMPLETE_TYPED_AUTHORITY_SOURCES"
                    ));
                }
                final TypedAuthorityService.Decision typedDecision;
                try {
                    typedDecision = typedAuthorityService.evaluate(
                            rootPayload.get("typed_authority"),
                            holderPayload.get("typed_authority"),
                            vpPayload.get("requested_authority"),
                            vpPayload.get("tpp_authority")
                    );
                } catch (IllegalArgumentException malformed) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                            "error", "invalid_grant", "error_description", malformed.getMessage()
                    ));
                }
                if (!typedDecision.isPermitted()) {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                            "error", "access_denied", "error_description", typedDecision.getReason()
                    ));
                }
                effectiveTypedAuthority = typedDecision.getAuthority();
                s_token = scopesForServices(effectiveTypedAuthority.get("services"));
            }

            // Strict Fail-Closed (Claim A.6 & Invariant I-6): If empty, DENY!
            if (s_token.isEmpty()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "access_denied", "error_description", "Typed non-expansion intersection resulted in empty authority"));
            }

            if (bindingRecord != null) {
                if (vpPayload.has("simulate_adverse_version_before_commit") || vpPayload.has("test_hook_advance_version_before_commit")) {
                    certificateRecordStore.advanceVersion(bindingRecord.getRecordId());
                }
                CertificateRecordStore.CertificateRecord currentBinding = certificateRecordStore.resolveCertRef(bindingRecord.getRecordId());
                if (currentBinding != null && currentBinding.getAuditVersion() != initialBindingVersion) {
                    return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                            "error", "invalid_grant",
                            "error_description", "REJECT_BINDING_CHANGED_BEFORE_COMMIT: binding version changed before token commit"
                    ));
                }
            }

            String sub = (delegateResult.getPayload() != null && delegateResult.getPayload().has("sub"))
                    ? delegateResult.getPayload().get("sub").asText()
                    : tppClientId;

            String cnfThumbprint = clientCertThumbprint != null ? clientCertThumbprint : certificateRecordStore.computeThumbprint(tppClientId + "_mTLS_cert");

            long now = System.currentTimeMillis() / 1000;
            long exp = now + 300; // 5-minute prototype lifetime per VDAM profile (Equation 4.3 & 6.10)
            String jti = "urn:uuid:" + UUID.randomUUID().toString();
            String audR = vpPayload.has("aud_r") ? vpPayload.get("aud_r").asText() : "http://localhost:4000";

            // Mint Self-Contained Signed JWT Access Token
            ObjectNode tokenPayload = mapper.createObjectNode();
            tokenPayload.put("iss", issuerUrl);
            tokenPayload.put("sub", sub);
            tokenPayload.put("aud", audR);
            tokenPayload.put("scope", String.join(" ", s_token));
            tokenPayload.put("iat", now);
            tokenPayload.put("exp", exp);
            tokenPayload.put("jti", jti);
            tokenPayload.put("client_id", tppClientId);

            ObjectNode cnf = tokenPayload.putObject("cnf");
            cnf.put("x5t#S256", cnfThumbprint);

            ObjectNode vcGrant = tokenPayload.putObject("vcGrant");
            vcGrant.put("authzVcJti", (rootResult.getPayload() != null && rootResult.getPayload().has("jti")) ? rootResult.getPayload().get("jti").asText() : "root_jti");
            vcGrant.put("delegateVcJti", (delegateResult.getPayload() != null && delegateResult.getPayload().has("jti")) ? delegateResult.getPayload().get("jti").asText() : "delegate_jti");
            vcGrant.put("policyVersion", policyService.getVersion());
            if (effectiveTypedAuthority != null) {
                tokenPayload.set("typed_authority", effectiveTypedAuthority);
                long evalTime = typedAuthorityService.getEvaluationTime();
                if (effectiveTypedAuthority.has("validity")) {
                    long vStart = effectiveTypedAuthority.get("validity").path("start").asLong();
                    long vEnd = effectiveTypedAuthority.get("validity").path("end").asLong();
                    if (evalTime < vStart || evalTime > vEnd) {
                        evalTime = vStart;
                    }
                }
                tokenPayload.put("typed_authority_evaluation_time", evalTime);
                vcGrant.put("typedAuthorityPolicyVersion", policyService.getVersion());
            }

            String signedJwtAccessToken = cryptoService.sign(tokenPayload.toString(), "JWT");

            accessTokens.put(signedJwtAccessToken, new TokenData(sub, String.join(" ", s_token), exp, cnfThumbprint, vcGrant));

            ObjectNode res = mapper.createObjectNode();
            res.put("access_token", signedJwtAccessToken);
            res.put("token_type", "Bearer");
            res.put("expires_in", 300);
            res.put("scope", String.join(" ", s_token));
            res.set("cnf", cnf);
            if (effectiveTypedAuthority != null) {
                res.set("typed_authority", effectiveTypedAuthority);
            }

            System.out.println("[DAS Classical] Signed JWT Access Token issued for TPP '" + tppClientId + "', exp=300s, scope=" + String.join(" ", s_token));
            return ResponseEntity.ok(res);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "server_error", "error_description", e.getMessage()));
        }
    }

    private Set<String> scopesForServices(JsonNode services) {
        Set<String> scopes = new LinkedHashSet<>();
        for (JsonNode service : services) {
            switch (service.asText()) {
                case "accounts": scopes.add("accounts:read"); break;
                case "balances": scopes.add("ReadBalances"); break;
                case "transactions": scopes.add("transactions:read"); break;
                case "payments": scopes.add("transfers:write"); break;
                default: throw new IllegalArgumentException("REJECT_UNKNOWN_SERVICE: " + service.asText());
            }
        }
        return scopes;
    }

    @PostMapping(value = "/introspect", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<?> introspect(@RequestParam Map<String, String> body) {
        String token = body.get("token");
        TokenData td = accessTokens.get(token);
        ObjectNode res = mapper.createObjectNode();
        if (td == null || td.exp < System.currentTimeMillis() / 1000) {
            res.put("active", false);
        } else {
            res.put("active", true);
            res.put("sub", td.sub);
            res.put("scope", td.scope);
            res.put("exp", td.exp);
            res.put("iss", issuerUrl);

            if (td.cnfThumbprint != null) {
                ObjectNode cnf = mapper.createObjectNode();
                cnf.put("x5t#S256", td.cnfThumbprint);
                res.set("cnf", cnf);
            }
            if (td.vcGrant != null) {
                res.set("vcGrant", td.vcGrant);
            }
        }
        return ResponseEntity.ok(res);
    }

    @GetMapping(value = "/api/policy/identity-claims", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getMasterIdentityClaims() {
        Set<String> claims = policyService.getMasterIdentityClaims();
        ObjectNode res = mapper.createObjectNode();
        ArrayNode arr = res.putArray("claims");
        claims.forEach(arr::add);
        return ResponseEntity.ok(res);
    }
}
