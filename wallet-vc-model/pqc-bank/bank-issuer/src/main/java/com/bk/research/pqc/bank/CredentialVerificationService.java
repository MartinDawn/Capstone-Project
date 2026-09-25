package com.bk.research.pqc.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class CredentialVerificationService {

    @Autowired
    private CertificateRecordStore certificateRecordStore;

    @Autowired
    private CryptoService cryptoService;

    private final ObjectMapper mapper = new ObjectMapper();

    public static final Map<String, Set<String>> SCOPE_SYNONYMS = new HashMap<>();
    static {
        SCOPE_SYNONYMS.put("accounts:read", new HashSet<>(Arrays.asList("accounts:read", "ReadAccountsBasic", "ReadAccountsDetail", "ReadBalances")));
        SCOPE_SYNONYMS.put("ReadAccountsDetail", new HashSet<>(Arrays.asList("ReadAccountsDetail", "accounts:read", "ReadAccountsBasic", "ReadBalances")));
        SCOPE_SYNONYMS.put("ReadAccountsBasic", new HashSet<>(Arrays.asList("ReadAccountsBasic", "accounts:read")));
        SCOPE_SYNONYMS.put("ReadBalances", new HashSet<>(Arrays.asList("ReadBalances", "accounts:read")));
        SCOPE_SYNONYMS.put("transfers:read", new HashSet<>(Arrays.asList("transfers:read", "transactions:read", "ReadTransactionsBasic", "ReadTransactionsDetail", "ReadTransactionsCredits", "ReadTransactionsDebits")));
        SCOPE_SYNONYMS.put("transactions:read", new HashSet<>(Arrays.asList("transactions:read", "transfers:read", "ReadTransactionsBasic", "ReadTransactionsDetail", "ReadTransactionsCredits", "ReadTransactionsDebits")));
        SCOPE_SYNONYMS.put("ReadTransactionsDetail", new HashSet<>(Arrays.asList("ReadTransactionsDetail", "transfers:read", "transactions:read", "ReadTransactionsBasic")));
        SCOPE_SYNONYMS.put("ReadTransactionsBasic", new HashSet<>(Arrays.asList("ReadTransactionsBasic", "transfers:read", "transactions:read")));
        SCOPE_SYNONYMS.put("transfers:write", new HashSet<>(Arrays.asList("transfers:write", "CreateDomesticPayment")));
        SCOPE_SYNONYMS.put("CreateDomesticPayment", new HashSet<>(Arrays.asList("CreateDomesticPayment", "transfers:write")));
        SCOPE_SYNONYMS.put("profile:read", new HashSet<>(Collections.singletonList("profile:read")));
    }

    public static boolean isContained(String targetScope, Collection<String> rootScopes) {
        if (rootScopes == null || rootScopes.isEmpty()) return false;
        if (rootScopes.contains(targetScope) || rootScopes.contains("*") || rootScopes.contains("banking")) {
            return true;
        }
        Set<String> synonyms = SCOPE_SYNONYMS.get(targetScope);
        if (synonyms != null) {
            for (String s : synonyms) {
                if (rootScopes.contains(s)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Does this presentation carry its own Holder key material and verify under it instead of under the
     * issuer-protected key from the issuance record? Used only to classify a rejection: key material
     * advertised inside the presentation is never accepted as a verification key.
     */
    private boolean verifiesUnderAdvertisedKey(String signingInput, byte[] signatureBytes, JsonNode payload,
                                               CertificateRecordStore.CertificateRecord record) {
        if (payload == null) return false;
        for (String claim : new String[] {"wallet_ec_jwk", "holder_key_hint"}) {
            if (!payload.has(claim)) continue;
            String advertised = payload.get(claim).isTextual()
                    ? payload.get(claim).asText()
                    : payload.get(claim).toString();
            if (advertised == null || advertised.isBlank() || advertised.equals(record.getRawJwkJson())) continue;
            String advertisedPqc = payload.path("wallet_pqc_public_key").asText(null);
            try {
                com.nimbusds.jose.jwk.ECKey advertisedKey = com.nimbusds.jose.jwk.ECKey.parse(advertised);
                boolean verified = cryptoService.verifyHybridSignature(
                    signingInput,
                    signatureBytes,
                    advertisedKey.toECPublicKey(),
                    advertisedPqc != null ? decodeBase64Url(advertisedPqc) : null,
                    "p384_mldsa65"
                );
                if (verified) {
                    return true;
                }
            } catch (Exception ignored) {
                // Unparsable or non-matching hint: not evidence of a substitution attempt.
            }
        }
        return false;
    }

    private byte[] decodeBase64Url(String input) {
        if (input == null || input.isEmpty()) return new byte[0];
        try {
            return java.util.Base64.getUrlDecoder().decode(input);
        } catch (IllegalArgumentException e) {
            try {
                return java.util.Base64.getDecoder().decode(input);
            } catch (Exception ex) {
                // If missing padding, try adding padding
                String padded = input;
                while (padded.length() % 4 != 0) {
                    padded += "=";
                }
                try {
                    return java.util.Base64.getUrlDecoder().decode(padded);
                } catch (Exception ex2) {
                    try {
                        return java.util.Base64.getDecoder().decode(padded);
                    } catch (Exception ex3) {
                        return new byte[0];
                    }
                }
            }
        }
    }

    public static class VerificationResult {
        private final boolean valid;
        private final String errorMessage;
        private final JsonNode payload;
        private final JsonNode header;
        private final CertificateRecordStore.CertificateRecord certRecord;
        private final List<String> scopes;

        public VerificationResult(boolean valid, String errorMessage, JsonNode header, JsonNode payload, CertificateRecordStore.CertificateRecord certRecord, List<String> scopes) {
            this.valid = valid;
            this.errorMessage = errorMessage;
            this.header = header;
            this.payload = payload;
            this.certRecord = certRecord;
            this.scopes = scopes != null ? scopes : Collections.emptyList();
        }

        public boolean isValid() { return valid; }
        public String getErrorMessage() { return errorMessage; }
        public JsonNode getHeader() { return header; }
        public JsonNode getPayload() { return payload; }
        public CertificateRecordStore.CertificateRecord getCertRecord() { return certRecord; }
        public List<String> getScopes() { return scopes; }
    }

    /**
     * Independently verify the presented Root Scope VC (AuthorizationCredential SD-JWT)
     */
    public VerificationResult verifyRootScopeVc(String sdJwtStr, String bankIssuerUrl) {
        try {
            if (sdJwtStr == null || sdJwtStr.isEmpty()) {
                return new VerificationResult(false, "REJECT_MISSING_ROOT_VC: Root Scope VC is missing", null, null, null, null);
            }

            String[] parts = sdJwtStr.split("~");
            String jwtPart = parts[0];
            String[] jwtSections = jwtPart.split("\\.");
            if (jwtSections.length < 3) {
                return new VerificationResult(false, "REJECT_MALFORMED_ROOT_VC: Malformed Root Scope VC JWT structure", null, null, null, null);
            }

            String headerStr = new String(decodeBase64Url(jwtSections[0]), StandardCharsets.UTF_8);
            String payloadStr = new String(decodeBase64Url(jwtSections[1]), StandardCharsets.UTF_8);
            JsonNode header = mapper.readTree(headerStr);
            JsonNode payload = mapper.readTree(payloadStr);

            List<String> scopes;
            try {
                scopes = extractScopesFromSdJwt(parts, payload);
            } catch (IllegalArgumentException iae) {
                return new VerificationResult(false, iae.getMessage(), header, payload, null, null);
            }

            if (payload.has("_sd") && scopes.isEmpty()) {
                return new VerificationResult(false, "REJECT_MISSING_REQUIRED_DISCLOSURE: Root Scope VC is missing policy-required scopes disclosure", header, payload, null, scopes);
            }

            // 1. Verify Issuer
            String iss = payload.has("iss") ? payload.get("iss").asText() : "";
            if (!iss.equals(bankIssuerUrl) && !iss.contains("bank-issuer") && !iss.contains("localhost:7000")) {
                return new VerificationResult(false, "REJECT_UNTRUSTED_ROOT_VC_ISSUER: Untrusted Root Scope VC issuer: " + iss, header, payload, null, scopes);
            }

            // 2. Verify Expiration
            long now = System.currentTimeMillis() / 1000;
            if (payload.has("exp") && payload.get("exp").asLong() < now) {
                return new VerificationResult(false, "REJECT_REVOKED_OR_EXPIRED_CREDENTIAL: Root Scope VC has expired", header, payload, null, scopes);
            }

            // 3. Verify Hybrid Signature of Issuer
            byte[] hybridSigBytes = decodeBase64Url(jwtSections[2]);
            String signingInput = jwtSections[0] + "." + jwtSections[1];

            // Verify EC signature part using bank EC public key
            boolean sigOk = cryptoService.verifyHybridSignature(
                signingInput,
                hybridSigBytes,
                cryptoService.getEcJwk().toECPublicKey(),
                decodeBase64Url(cryptoService.getPqcPublicKeyBase64()),
                "MLDSA65"
            );
            if (!sigOk) {
                return new VerificationResult(false, "REJECT_INVALID_ROOT_VC_SIGNATURE: Root Scope VC hybrid signature verification failed", header, payload, null, scopes);
            }

            // 4. Resolve holder_cert_ref
            if (!certificateRecordStore.isLookupAvailable()) {
                return new VerificationResult(false, "REJECT_BINDING_LOOKUP_UNAVAILABLE: authoritative issuance-binding lookup service is unavailable", header, payload, null, scopes);
            }

            String holderCertRef = payload.has("holder_cert_ref") ? payload.get("holder_cert_ref").asText() : null;
            CertificateRecordStore.CertificateRecord record = null;
            if (holderCertRef == null || holderCertRef.isBlank()) {
                return new VerificationResult(false, "REJECT_MISSING_ISSUANCE_RECORD: Root Scope VC has no holder_cert_ref", header, payload, null, scopes);
            }
            if (holderCertRef != null) {
                record = certificateRecordStore.resolveCertRef(holderCertRef);
                if (record == null) {
                    return new VerificationResult(false, "REJECT_MISSING_ISSUANCE_RECORD: Unresolvable holder_cert_ref in Root Scope VC: " + holderCertRef, header, payload, null, scopes);
                }
                if (record.getStatus() != CertificateRecordStore.Status.ACTIVE) {
                    String rejection = record.getStatus() == CertificateRecordStore.Status.REVOKED
                            ? "REJECT_REVOKED_OR_EXPIRED_CREDENTIAL"
                            : "REJECT_DISABLED_ASSOCIATION";
                    return new VerificationResult(false, rejection + ": Holder certificate record is " + record.getStatus(), header, payload, record, scopes);
                }
                if (record.isWalletCertInvalidated()) {
                    return new VerificationResult(false, "REJECT_WALLET_CERTIFICATE_INVALIDATED: Wallet certificate invalidated after F1", header, payload, record, scopes);
                }
                if (record.isHolderKeyInvalidated()) {
                    return new VerificationResult(false, "REJECT_HOLDER_KEY_INVALIDATED: Holder verification key invalidated after F1", header, payload, record, scopes);
                }
                // Credential identity and the exact issuer-signed component must match the committed record.
                if (!java.util.Objects.equals(record.getCredentialId(), payload.path("jti").asText(null))
                        || !java.util.Objects.equals(record.getCredentialComponentDigest(), certificateRecordStore.computeThumbprint(jwtPart))) {
                    return new VerificationResult(false, "REJECT_MISMATCHED_ISSUANCE_RECORD: presented credential identity or issuer-signed component differs from the authoritative issuance record", header, payload, record, scopes);
                }
                if (!java.util.Objects.equals(record.getStatusListReference(), payload.path("credential_status_ref").asText(null))) {
                    return new VerificationResult(false, "REJECT_BINDING_CREDENTIAL_STATUS_MISMATCH: credential status reference differs from committed issuance state", header, payload, record, scopes);
                }
                if (!java.util.Objects.equals(record.getHolderSubject(), payload.path("holder_subject").asText(null))) {
                    return new VerificationResult(false, "REJECT_BINDING_HOLDER_MISMATCH: Holder differs from committed issuance state", header, payload, record, scopes);
                }
                if (!payload.has("cnf") || !payload.get("cnf").has("jwk")
                        || !java.util.Objects.equals(record.getRawJwkJson(), payload.get("cnf").get("jwk").toString())) {
                    return new VerificationResult(false, "REJECT_BINDING_KEY_SET_MISMATCH: Holder verification key set differs from committed issuance state", header, payload, record, scopes);
                }
                if (!java.util.Objects.equals(record.getCertThumbprint(), payload.path("wallet_certificate_thumbprint").asText(null))) {
                    return new VerificationResult(false, "REJECT_BINDING_WALLET_CERTIFICATE_MISMATCH: Wallet certificate thumbprint differs from committed issuance state", header, payload, record, scopes);
                }
                if (!java.util.Objects.equals(record.getBindingProfile(), payload.path("binding_profile").asText(null))) {
                    return new VerificationResult(false, "REJECT_BINDING_PROFILE_MISMATCH: cryptographic profile differs from committed issuance state", header, payload, record, scopes);
                }
                if (record.getValidFrom() != payload.path("iat").asLong()
                        || record.getValidUntil() != payload.path("exp").asLong()) {
                    return new VerificationResult(false, "REJECT_BINDING_CREDENTIAL_STATUS_MISMATCH: credential validity differs from committed issuance state", header, payload, record, scopes);
                }
            }

            return new VerificationResult(true, null, header, payload, record, scopes);

        } catch (Exception e) {
            return new VerificationResult(false, "Root Scope VC verification exception: " + e.getMessage(), null, null, null, null);
        }
    }

    /**
     * Independently verify the Delegation VC against the validated Root Scope VC and expected TPP delegate
     */
    public VerificationResult verifyDelegationVc(String delegateSdJwtStr, VerificationResult rootResult, String expectedDelegateClientId) {
        try {
            if (delegateSdJwtStr == null || delegateSdJwtStr.isEmpty()) {
                return new VerificationResult(false, "REJECT_MISSING_DELEGATION_VC: Delegation VC is missing", null, null, null, null);
            }

            String[] parts = delegateSdJwtStr.split("~");
            String jwtPart = parts[0];
            String[] jwtSections = jwtPart.split("\\.");
            if (jwtSections.length < 3) {
                return new VerificationResult(false, "REJECT_MALFORMED_DELEGATION_VC: Malformed Delegation VC JWT structure", null, null, null, null);
            }

            String headerStr = new String(decodeBase64Url(jwtSections[0]), StandardCharsets.UTF_8);
            String payloadStr = new String(decodeBase64Url(jwtSections[1]), StandardCharsets.UTF_8);
            JsonNode header = mapper.readTree(headerStr);
            JsonNode payload = mapper.readTree(payloadStr);

            // Extract delegated scopes early
            List<String> delegatedScopes = new ArrayList<>();
            if (payload.has("delegated_scopes") && payload.get("delegated_scopes").isArray()) {
                for (JsonNode sn : payload.get("delegated_scopes")) {
                    delegatedScopes.add(sn.asText());
                }
            }
            List<String> sdScopes = extractScopesFromSdJwt(parts, payload);
            for (String s : sdScopes) {
                if (!delegatedScopes.contains(s)) {
                    delegatedScopes.add(s);
                }
            }

            // 1. Verify Expiration
            long now = System.currentTimeMillis() / 1000;
            if (payload.has("exp") && payload.get("exp").asLong() < now) {
                return new VerificationResult(false, "REJECT_REVOKED_OR_EXPIRED_CREDENTIAL: Delegation VC has expired", header, payload, null, delegatedScopes);
            }

            // 2. Verify Delegate Subject matches authenticated TPP client ID
            String sub = payload.has("sub") ? payload.get("sub").asText() : "";
            if (!sub.isEmpty() && expectedDelegateClientId != null && !sub.equals(expectedDelegateClientId)) {
                return new VerificationResult(false, "REJECT_WRONG_DELEGATION_SIGNER: Delegation VC subject ('" + sub + "') does not match authenticated TPP client ('" + expectedDelegateClientId + "')", header, payload, null, delegatedScopes);
            }

            // 3. Verify parent_vc_jti matches Root Scope VC JTI
            String parentJti = payload.has("parent_vc_jti") ? payload.get("parent_vc_jti").asText() : "";
            String rootJti = rootResult != null && rootResult.getPayload() != null && rootResult.getPayload().has("jti") ? rootResult.getPayload().get("jti").asText() : "";
            if (!parentJti.isEmpty() && !rootJti.isEmpty() && !parentJti.equals(rootJti)) {
                return new VerificationResult(false, "REJECT_MISMATCHED_ISSUANCE_CONTEXT: Delegation VC parent_vc_jti ('" + parentJti + "') does not match Root VC JTI ('" + rootJti + "')", header, payload, null, delegatedScopes);
            }

            // 3b. Prove Containment: delegated_scopes ⊆ rootScopes (Typed Non-Expansion with semantic alias tolerance)
            List<String> rootScopes = rootResult != null ? rootResult.getScopes() : null;
            if (rootScopes != null && !rootScopes.isEmpty()) {
                for (String ds : delegatedScopes) {
                    if (!isContained(ds, rootScopes)) {
                        return new VerificationResult(false, "REJECT_UNAUTHORIZED_AUTHORITY_EXPANSION: Scope containment violation: Delegated scope '" + ds + "' exceeds Root Scope VC ceiling " + rootScopes, header, payload, null, delegatedScopes);
                    }
                }
            }

            // 4. Verify Holder Chained Proof (Proof-of-possession) under Holder key
            CertificateRecordStore.CertificateRecord certRecord = rootResult != null ? rootResult.getCertRecord() : null;
            if (certRecord == null || certRecord.getRawJwkJson() == null || certRecord.getRawJwkJson().isEmpty()) {
                return new VerificationResult(false, "REJECT_MISSING_ISSUANCE_RECORD: Missing Holder certificate record for Delegation VC verification", header, payload, null, delegatedScopes);
            }

            byte[] hybridSigBytes = decodeBase64Url(jwtSections[2]);
            String signingInput = jwtSections[0] + "." + jwtSections[1];

            try {
                com.nimbusds.jose.jwk.ECKey holderKey = com.nimbusds.jose.jwk.ECKey.parse(certRecord.getRawJwkJson());
                boolean holderSigOk = cryptoService.verifyHybridSignature(
                    signingInput,
                    hybridSigBytes,
                    holderKey.toECPublicKey(),
                    certRecord.getPqcPublicKeyBase64() != null ? decodeBase64Url(certRecord.getPqcPublicKeyBase64()) : null,
                    "p384_mldsa65"
                );
                if (!holderSigOk) {
                    // The signature does not verify under the issuer-protected Holder key. Distinguish a
                    // key-substitution attempt (the presentation advertises another key and is signed with it)
                    // from a plain broken signature. The advertised key is never trusted either way.
                    String rejection = verifiesUnderAdvertisedKey(signingInput, hybridSigBytes, payload, certRecord)
                            ? "REJECT_SUBSTITUTED_HOLDER_KEY"
                            : "REJECT_INVALID_DELEGATION_VC_SIGNATURE";
                    return new VerificationResult(false, rejection + ": Delegation VC signature verification under authoritative Holder hybrid key failed", header, payload, certRecord, delegatedScopes);
                }
            } catch (Exception sigEx) {
                return new VerificationResult(false, "REJECT_INVALID_DELEGATION_VC_SIGNATURE: Error verifying Holder signature on Delegation VC: " + sigEx.getMessage(), header, payload, certRecord, delegatedScopes);
            }

            // 5. Verify RFC 9901 Key Binding JWT (KB-JWT) if present
            if (parts.length > 1 && !parts[parts.length - 1].isEmpty()) {
                String kbJwtStr = parts[parts.length - 1];
                String[] kbSections = kbJwtStr.split("\\.");
                if (kbSections.length >= 2) {
                    try {
                        JsonNode kbPayload = mapper.readTree(new String(decodeBase64Url(kbSections[1]), StandardCharsets.UTF_8));

                        // Validate sd_hash: SHA-384 digest of everything preceding the KB-JWT
                        int lastTilde = delegateSdJwtStr.lastIndexOf('~');
                        String sdPartToHash = delegateSdJwtStr.substring(0, lastTilde + 1);
                        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-384");
                        byte[] expectedHashBytes = md.digest(sdPartToHash.getBytes(StandardCharsets.UTF_8));
                        String calculatedSdHash = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedHashBytes);

                        if (kbPayload.has("sd_hash")) {
                            String presentedSdHash = kbPayload.get("sd_hash").asText();
                            if (!presentedSdHash.equals(calculatedSdHash)) {
                                return new VerificationResult(false, "REJECT_CORRUPTED_SD_HASH: selective disclosure hash mismatch in KB-JWT", header, payload, certRecord, delegatedScopes);
                            }
                        }

                        if (kbPayload.has("exp") && kbPayload.get("exp").asLong() < now) {
                            return new VerificationResult(false, "KB-JWT has expired", header, payload, certRecord, delegatedScopes);
                        }

                        // Cryptographic verification of RFC 9901 KB-JWT signature under Holder key
                        if (kbSections.length == 3) {
                            String kbSigningInput = kbSections[0] + "." + kbSections[1];
                            byte[] kbSigBytes = decodeBase64Url(kbSections[2]);
                            com.nimbusds.jose.jwk.ECKey holderKey = com.nimbusds.jose.jwk.ECKey.parse(certRecord.getRawJwkJson());
                            boolean kbSigValid = cryptoService.verifyHybridSignature(
                                kbSigningInput,
                                kbSigBytes,
                                holderKey.toECPublicKey(),
                                certRecord.getPqcPublicKeyBase64() != null ? decodeBase64Url(certRecord.getPqcPublicKeyBase64()) : null,
                                "p384_mldsa65"
                            );
                            if (!kbSigValid) {
                                return new VerificationResult(false, "REJECT_INVALID_KB_JWT_SIGNATURE: RFC 9901 KB-JWT signature verification failed under Holder key", header, payload, certRecord, delegatedScopes);
                            }
                        } else {
                            return new VerificationResult(false, "REJECT_MALFORMED_KB_JWT: KB-JWT must contain 3 sections", header, payload, certRecord, delegatedScopes);
                        }
                    } catch (Exception kbEx) {
                        return new VerificationResult(false, "Error verifying KB-JWT in Delegation VC: " + kbEx.getMessage(), header, payload, certRecord, delegatedScopes);
                    }
                }
            }

            return new VerificationResult(true, null, header, payload, certRecord, delegatedScopes);

        } catch (Exception e) {
            return new VerificationResult(false, "Delegation VC verification exception: " + e.getMessage(), null, null, null, null);
        }
    }

    private List<String> extractScopesFromSdJwt(String[] parts, JsonNode payload) throws Exception {
        List<String> scopes = new ArrayList<>();
        if (payload != null && payload.has("scopes") && payload.get("scopes").isArray()) {
            for (JsonNode s : payload.get("scopes")) {
                scopes.add(s.asText());
            }
        }

        Set<String> validSdHashes = new HashSet<>();
        if (payload != null && payload.has("_sd") && payload.get("_sd").isArray()) {
            for (JsonNode h : payload.get("_sd")) {
                validSdHashes.add(h.asText());
            }
        }

        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-384");

        for (int i = 1; i < parts.length; i++) {
            if (parts[i].isEmpty()) continue;
            if (parts[i].contains(".")) continue; // Skip KB-JWT if present at the end

            // Verify disclosure digest under SHA-384 against _sd if present
            if (!validSdHashes.isEmpty()) {
                byte[] hash = md.digest(parts[i].getBytes(StandardCharsets.UTF_8));
                String hashB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                if (!validSdHashes.contains(hashB64)) {
                    throw new IllegalArgumentException("REJECT_DISCLOSURE_SET_MISMATCH: presented disclosure digest is not in _sd array");
                }
            }

            try {
                byte[] decoded = decodeBase64Url(parts[i]);
                JsonNode arr = mapper.readTree(new String(decoded, StandardCharsets.UTF_8));
                if (arr.isArray() && arr.size() == 3) {
                    String key = arr.get(1).asText();
                    if ("scopes".equals(key) && arr.get(2).isArray()) {
                        for (JsonNode sn : arr.get(2)) {
                            if (!scopes.contains(sn.asText())) {
                                scopes.add(sn.asText());
                            }
                        }
                    }
                }
            } catch (Exception ignored) {}
        }
        return scopes;
    }
}
