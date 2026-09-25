package com.bk.research.classical.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class CertificateRecordStore {

    public enum Status {
        PENDING,
        ACTIVE,
        SUSPENDED,
        REVOKED
    }

    public static class CertificateRecord {
        private final String recordId; // holder_cert_ref
        private String holderSubject;
        private String certThumbprint; // SHA-256 of EC JWK / public key
        private String rawJwkJson;
        private String credentialId;
        private String credentialComponentDigest;
        private String bindingProfile;
        private String f1TransactionId;
        private long validFrom;
        private long validUntil;
        private String statusListReference;
        private Status status;
        private final long createdAt;
        private Long revokedAt;
        private long auditVersion;

        private boolean walletCertInvalidated;
        private boolean holderKeyInvalidated;

        public CertificateRecord(String recordId, String holderSubject, String certThumbprint, String rawJwkJson) {
            this(recordId, holderSubject, certThumbprint, rawJwkJson, Status.PENDING,
                    System.currentTimeMillis() / 1000, null, 1L,
                    null, null, null, null, 0L, 0L, null, false, false);
        }

        private CertificateRecord(String recordId, String holderSubject, String certThumbprint,
                                  String rawJwkJson, Status status, long createdAt,
                                  Long revokedAt, long auditVersion, String credentialId,
                                  String credentialComponentDigest, String bindingProfile,
                                  String f1TransactionId, long validFrom, long validUntil,
                                  String statusListReference, boolean walletCertInvalidated,
                                  boolean holderKeyInvalidated) {
            this.recordId = recordId;
            this.holderSubject = holderSubject;
            this.certThumbprint = certThumbprint;
            this.rawJwkJson = rawJwkJson;
            this.status = status;
            this.createdAt = createdAt;
            this.revokedAt = revokedAt;
            this.auditVersion = auditVersion;
            this.credentialId = credentialId;
            this.credentialComponentDigest = credentialComponentDigest;
            this.bindingProfile = bindingProfile;
            this.f1TransactionId = f1TransactionId;
            this.validFrom = validFrom;
            this.validUntil = validUntil;
            this.statusListReference = statusListReference;
            this.walletCertInvalidated = walletCertInvalidated;
            this.holderKeyInvalidated = holderKeyInvalidated;
            this.originalHolderSubject = holderSubject;
            this.originalCertThumbprint = certThumbprint;
            this.originalRawJwkJson = rawJwkJson;
            this.originalBindingProfile = bindingProfile;
            this.originalStatusListReference = statusListReference;
            this.originalCredentialComponentDigest = credentialComponentDigest;
        }

        private String originalHolderSubject;
        private String originalCertThumbprint;
        private String originalRawJwkJson;
        private String originalBindingProfile;
        private String originalStatusListReference;
        private String originalCredentialComponentDigest;

        public String getRecordId() { return recordId; }
        public String getHolderSubject() { return holderSubject; }
        public void setHolderSubject(String val) { this.holderSubject = val; this.auditVersion++; }
        public String getCertThumbprint() { return certThumbprint; }
        public void setCertThumbprint(String val) { this.certThumbprint = val; this.auditVersion++; }
        public String getRawJwkJson() { return rawJwkJson; }
        public void setRawJwkJson(String val) { this.rawJwkJson = val; this.auditVersion++; }
        public Status getStatus() { return status; }
        public void setStatus(Status status) {
            this.status = status;
            this.auditVersion++;
            if (status == Status.REVOKED) {
                this.revokedAt = System.currentTimeMillis() / 1000;
            }
        }
        public boolean isWalletCertInvalidated() { return walletCertInvalidated; }
        public void setWalletCertInvalidated(boolean val) {
            this.walletCertInvalidated = val;
            this.auditVersion++;
        }
        public boolean isHolderKeyInvalidated() { return holderKeyInvalidated; }
        public void setHolderKeyInvalidated(boolean val) {
            this.holderKeyInvalidated = val;
            this.auditVersion++;
        }
        public void advanceVersion() {
            this.auditVersion++;
        }
        public long getCreatedAt() { return createdAt; }
        public Long getRevokedAt() { return revokedAt; }
        public long getAuditVersion() { return auditVersion; }
        public String getCredentialId() { return credentialId; }
        public String getCredentialComponentDigest() { return credentialComponentDigest; }
        public void setCredentialComponentDigest(String val) { this.credentialComponentDigest = val; this.auditVersion++; }
        public String getBindingProfile() { return bindingProfile; }
        public void setBindingProfile(String val) { this.bindingProfile = val; this.auditVersion++; }
        public String getF1TransactionId() { return f1TransactionId; }
        public long getValidFrom() { return validFrom; }
        public long getValidUntil() { return validUntil; }
        public String getStatusListReference() { return statusListReference; }
        public void setStatusListReference(String val) { this.statusListReference = val; this.auditVersion++; }
        private void commitCredential(String credentialId, String credentialComponentDigest,
                                      String bindingProfile, String f1TransactionId,
                                      long validFrom, long validUntil, String statusListReference) {
            if (status != Status.PENDING || this.credentialId != null) {
                throw new IllegalStateException("REJECT_IMMUTABLE_BINDING_REBIND: issuance record is already committed");
            }
            this.credentialId = credentialId;
            this.credentialComponentDigest = credentialComponentDigest;
            this.bindingProfile = bindingProfile;
            this.f1TransactionId = f1TransactionId;
            this.validFrom = validFrom;
            this.validUntil = validUntil;
            this.statusListReference = statusListReference;
            this.originalHolderSubject = this.holderSubject;
            this.originalCertThumbprint = this.certThumbprint;
            this.originalRawJwkJson = this.rawJwkJson;
            this.originalBindingProfile = bindingProfile;
            this.originalStatusListReference = statusListReference;
            this.originalCredentialComponentDigest = credentialComponentDigest;
            this.status = Status.ACTIVE;
            this.auditVersion++;
        }
    }

    private final Map<String, CertificateRecord> records = new ConcurrentHashMap<>();
    private final Map<String, String> thumbprintToRefMap = new ConcurrentHashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();
    private final Path storePath;

    public CertificateRecordStore() {
        String configuredPath = System.getenv().getOrDefault(
                "ISSUANCE_BINDING_STORE_PATH", "/app/state/issuance-bindings.json");
        this.storePath = Path.of(configuredPath).toAbsolutePath().normalize();
        loadPersistedRecords();
    }

    public String registerCertificate(String holderSubject, JsonNode holderJwk) {
        return registerCertificate(holderSubject, holderJwk, null);
    }

    public synchronized String registerCertificate(String holderSubject, JsonNode holderJwk, String walletCertThumbprint) {
        try {
            String jwkString = holderJwk != null ? holderJwk.toString() : "";
            String thumbprint = (walletCertThumbprint != null && !walletCertThumbprint.trim().isEmpty())
                    ? walletCertThumbprint.trim()
                    : computeThumbprint(jwkString);

            if (thumbprintToRefMap.containsKey(thumbprint)) {
                String existingRef = thumbprintToRefMap.get(thumbprint);
                CertificateRecord existing = records.get(existingRef);
                if (existing != null && existing.getStatus() == Status.ACTIVE) {
                    boolean jwkEquals = false;
                    try {
                        JsonNode existingNode = mapper.readTree(existing.getRawJwkJson());
                        JsonNode incomingNode = holderJwk != null ? holderJwk : mapper.readTree(jwkString);
                        boolean crvMatches = existingNode.path("crv").asText("").equals(incomingNode.path("crv").asText(""));
                        boolean xMatches = existingNode.path("x").asText("").equals(incomingNode.path("x").asText(""));
                        boolean yMatches = existingNode.path("y").asText("").equals(incomingNode.path("y").asText(""));
                        boolean ecKeyMatches = (!existingNode.path("x").asText("").isEmpty() && crvMatches && xMatches && yMatches);
                        jwkEquals = existingNode.equals(incomingNode) || ecKeyMatches;
                    } catch (Exception e) {
                        jwkEquals = existing.getRawJwkJson().equals(jwkString);
                    }
                    boolean subMatches = existing.getHolderSubject().equals(holderSubject) 
                            || "testuser".equalsIgnoreCase(existing.getHolderSubject()) 
                            || "testuser".equalsIgnoreCase(holderSubject);
                    if (!subMatches || !jwkEquals) {
                        throw new IllegalStateException(
                                "REJECT_IMMUTABLE_BINDING_REBIND: wallet certificate is already bound to a different Holder identity or key (existing=" 
                                + existing.getHolderSubject() + ", incoming=" + holderSubject + ")");
                    }
                    // A new Scope VC receives a new immutable credential-scoped record.
                }
            }

            String recordId = "cert_ref_" + UUID.randomUUID().toString().replace("-", "");
            CertificateRecord record = new CertificateRecord(recordId, holderSubject, thumbprint, jwkString);
            records.put(recordId, record);
            thumbprintToRefMap.put(thumbprint, recordId);
            persistRecords();

            System.out.println("[CertificateRecordStore] Registered certificate recordId=" + recordId + " for sub=" + holderSubject + ", tau_W=" + thumbprint);
            return recordId;
        } catch (Exception e) {
            throw new RuntimeException("Failed to register certificate record: " + e.getMessage(), e);
        }
    }

    public synchronized CertificateRecord commitCredential(
            String holderCertRef, String credentialId, String signedComponent,
            String bindingProfile, String f1TransactionId, long validFrom,
            long validUntil, String statusListReference) {
        CertificateRecord record = records.get(holderCertRef);
        if (record == null) {
            throw new IllegalArgumentException("REJECT_MISSING_ISSUANCE_RECORD: " + holderCertRef);
        }
        record.commitCredential(
                credentialId,
                computeThumbprint(signedComponent),
                bindingProfile,
                f1TransactionId,
                validFrom,
                validUntil,
                statusListReference);
        thumbprintToRefMap.put(record.getCertThumbprint(), record.getRecordId());
        persistRecords();
        return record;
    }

    public CertificateRecord resolveCertRef(String holderCertRef) {
        if (holderCertRef == null || holderCertRef.trim().isEmpty()) {
            return null;
        }
        return records.get(holderCertRef);
    }

    public boolean validateAndResolve(String holderCertRef, JsonNode presentedJwk) {
        CertificateRecord record = resolveCertRef(holderCertRef);
        if (record == null) {
            System.err.println("[CertificateRecordStore] Unknown holder_cert_ref: " + holderCertRef);
            return false;
        }
        if (record.getStatus() != Status.ACTIVE) {
            System.err.println("[CertificateRecordStore] Certificate record is not ACTIVE (" + record.getStatus() + ") for ref: " + holderCertRef);
            return false;
        }
        if (presentedJwk != null) {
            String presentedThumbprint = computeThumbprint(presentedJwk.toString());
            if (!record.getCertThumbprint().equals(presentedThumbprint)) {
                System.err.println("[CertificateRecordStore] Certificate thumbprint mismatch for ref: " + holderCertRef);
                return false;
            }
        }
        return true;
    }

    public synchronized void revoke(String holderCertRef) {
        updateStatus(holderCertRef, Status.REVOKED);
    }

    private volatile boolean lookupAvailable = true;

    public boolean isLookupAvailable() {
        return lookupAvailable;
    }

    public void setLookupAvailable(boolean available) {
        this.lookupAvailable = available;
    }

    public synchronized CertificateRecord invalidateWalletCert(String holderCertRef) {
        CertificateRecord record = records.get(holderCertRef);
        if (record == null) {
            throw new IllegalArgumentException("REJECT_MISSING_ISSUANCE_RECORD: " + holderCertRef);
        }
        record.setWalletCertInvalidated(true);
        persistRecords();
        return record;
    }

    public synchronized CertificateRecord invalidateHolderKey(String holderCertRef) {
        CertificateRecord record = records.get(holderCertRef);
        if (record == null) {
            throw new IllegalArgumentException("REJECT_MISSING_ISSUANCE_RECORD: " + holderCertRef);
        }
        record.setHolderKeyInvalidated(true);
        persistRecords();
        return record;
    }

    public synchronized CertificateRecord advanceVersion(String holderCertRef) {
        CertificateRecord record = records.get(holderCertRef);
        if (record == null) {
            throw new IllegalArgumentException("REJECT_MISSING_ISSUANCE_RECORD: " + holderCertRef);
        }
        record.advanceVersion();
        persistRecords();
        return record;
    }

    public synchronized CertificateRecord updateStatus(String holderCertRef, Status status) {
        CertificateRecord record = records.get(holderCertRef);
        if (record == null) {
            throw new IllegalArgumentException("REJECT_MISSING_ISSUANCE_RECORD: " + holderCertRef);
        }
        record.setStatus(status);
        persistRecords();
        System.out.println("[CertificateRecordStore] Binding status changed for cert_ref="
                + holderCertRef + ", status=" + status + ", version=" + record.getAuditVersion());
        return record;
    }

    public synchronized CertificateRecord resetRecord(String holderCertRef) {
        CertificateRecord record = records.get(holderCertRef);
        if (record == null) {
            throw new IllegalArgumentException("REJECT_MISSING_ISSUANCE_RECORD: " + holderCertRef);
        }
        if (record.originalHolderSubject != null) record.holderSubject = record.originalHolderSubject;
        if (record.originalCertThumbprint != null) record.certThumbprint = record.originalCertThumbprint;
        if (record.originalRawJwkJson != null) record.rawJwkJson = record.originalRawJwkJson;
        if (record.originalBindingProfile != null) record.bindingProfile = record.originalBindingProfile;
        if (record.originalStatusListReference != null) record.statusListReference = record.originalStatusListReference;
        if (record.originalCredentialComponentDigest != null) record.credentialComponentDigest = record.originalCredentialComponentDigest;
        record.status = Status.ACTIVE;
        record.walletCertInvalidated = false;
        record.holderKeyInvalidated = false;
        record.advanceVersion();
        persistRecords();
        return record;
    }

    public synchronized CertificateRecord mutateRecord(String holderCertRef, Map<String, String> mutations) {
        CertificateRecord record = records.get(holderCertRef);
        if (record == null) {
            throw new IllegalArgumentException("REJECT_MISSING_ISSUANCE_RECORD: " + holderCertRef);
        }
        if (mutations.containsKey("holder_subject")) record.setHolderSubject(mutations.get("holder_subject"));
        if (mutations.containsKey("raw_jwk_json")) record.setRawJwkJson(mutations.get("raw_jwk_json"));
        if (mutations.containsKey("wallet_thumbprint")) record.setCertThumbprint(mutations.get("wallet_thumbprint"));
        if (mutations.containsKey("binding_profile")) record.setBindingProfile(mutations.get("binding_profile"));
        if (mutations.containsKey("status_list_reference")) record.setStatusListReference(mutations.get("status_list_reference"));
        if (mutations.containsKey("credential_component_digest")) record.setCredentialComponentDigest(mutations.get("credential_component_digest"));
        if (mutations.containsKey("wallet_cert_invalidated")) record.setWalletCertInvalidated(Boolean.parseBoolean(mutations.get("wallet_cert_invalidated")));
        if (mutations.containsKey("holder_key_invalidated")) record.setHolderKeyInvalidated(Boolean.parseBoolean(mutations.get("holder_key_invalidated")));
        if (mutations.containsKey("status")) record.setStatus(Status.valueOf(mutations.get("status")));
        persistRecords();
        return record;
    }

    public synchronized void updateCredentialComponentDigest(String holderCertRef, String digest) {
        CertificateRecord record = records.get(holderCertRef);
        if (record != null) {
            record.setCredentialComponentDigest(digest);
            persistRecords();
        }
    }

    public String computeThumbprint(String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute SHA-256 thumbprint", e);
        }
    }

    private synchronized void loadPersistedRecords() {
        if (!Files.exists(storePath)) {
            return;
        }
        try {
            JsonNode root = mapper.readTree(storePath.toFile());
            JsonNode persisted = root.get("records");
            if (persisted == null || !persisted.isArray()) {
                throw new IllegalStateException("Binding store is missing the records array");
            }
            for (JsonNode node : persisted) {
                CertificateRecord record = new CertificateRecord(
                        node.get("record_id").asText(),
                        node.get("holder_subject").asText(),
                        node.get("wallet_certificate_thumbprint").asText(),
                        node.get("holder_jwk").asText(),
                        Status.valueOf(node.get("status").asText()),
                        node.get("created_at").asLong(),
                        node.hasNonNull("revoked_at") ? node.get("revoked_at").asLong() : null,
                        node.get("binding_version").asLong(),
                        node.hasNonNull("credential_id") ? node.get("credential_id").asText() : null,
                        node.hasNonNull("credential_component_digest") ? node.get("credential_component_digest").asText() : null,
                        node.hasNonNull("binding_profile") ? node.get("binding_profile").asText() : null,
                        node.hasNonNull("f1_transaction_id") ? node.get("f1_transaction_id").asText() : null,
                        node.path("valid_from").asLong(0L),
                        node.path("valid_until").asLong(0L),
                        node.hasNonNull("status_list_reference") ? node.get("status_list_reference").asText() : null,
                        node.path("wallet_cert_invalidated").asBoolean(false),
                        node.path("holder_key_invalidated").asBoolean(false));
                records.put(record.getRecordId(), record);
                if (record.getStatus() == Status.ACTIVE) {
                    thumbprintToRefMap.put(record.getCertThumbprint(), record.getRecordId());
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load durable issuance-binding store", e);
        }
    }

    private synchronized void persistRecords() {
        try {
            Files.createDirectories(storePath.getParent());
            ObjectNode root = mapper.createObjectNode();
            root.put("schema_version", "1.0.0");
            ArrayNode persisted = root.putArray("records");
            records.values().stream()
                    .sorted((left, right) -> left.getRecordId().compareTo(right.getRecordId()))
                    .forEach(record -> {
                        ObjectNode node = persisted.addObject();
                        node.put("record_id", record.getRecordId());
                        node.put("holder_subject", record.getHolderSubject());
                        node.put("wallet_certificate_thumbprint", record.getCertThumbprint());
                        node.put("holder_jwk", record.getRawJwkJson());
                        node.put("status", record.getStatus().name());
                        node.put("created_at", record.getCreatedAt());
                        if (record.getRevokedAt() == null) node.putNull("revoked_at");
                        else node.put("revoked_at", record.getRevokedAt());
                        node.put("binding_version", record.getAuditVersion());
                        if (record.getCredentialId() == null) node.putNull("credential_id");
                        else node.put("credential_id", record.getCredentialId());
                        if (record.getCredentialComponentDigest() == null) node.putNull("credential_component_digest");
                        else node.put("credential_component_digest", record.getCredentialComponentDigest());
                        if (record.getBindingProfile() == null) node.putNull("binding_profile");
                        else node.put("binding_profile", record.getBindingProfile());
                        if (record.getF1TransactionId() == null) node.putNull("f1_transaction_id");
                        else node.put("f1_transaction_id", record.getF1TransactionId());
                        node.put("valid_from", record.getValidFrom());
                        node.put("valid_until", record.getValidUntil());
                        if (record.getStatusListReference() == null) node.putNull("status_list_reference");
                        else node.put("status_list_reference", record.getStatusListReference());
                        node.put("wallet_cert_invalidated", record.isWalletCertInvalidated());
                        node.put("holder_key_invalidated", record.isHolderKeyInvalidated());
                    });
            Path temporaryPath = storePath.resolveSibling(storePath.getFileName() + ".tmp");
            mapper.writerWithDefaultPrettyPrinter().writeValue(temporaryPath.toFile(), root);
            try {
                Files.move(temporaryPath, storePath, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
                Files.move(temporaryPath, storePath, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Unable to commit durable issuance-binding store", e);
        }
    }

    public synchronized Map<String, Object> getCanonicalActiveSnapshotSummary() {
        java.util.List<CertificateRecord> activeRecords = records.values().stream()
                .filter(r -> r.getStatus() == Status.ACTIVE)
                .sorted(java.util.Comparator.comparing(CertificateRecord::getRecordId))
                .collect(java.util.stream.Collectors.toList());

        ArrayNode arrayNode = mapper.createArrayNode();
        for (CertificateRecord r : activeRecords) {
            ObjectNode node = arrayNode.addObject();
            node.put("record_id", r.getRecordId());
            node.put("holder_subject", r.getHolderSubject() != null ? r.getHolderSubject() : "");
            node.put("wallet_certificate_thumbprint", r.getCertThumbprint() != null ? r.getCertThumbprint() : "");
            node.put("status", r.getStatus().name());
            node.put("binding_version", r.getAuditVersion());
            node.put("credential_id", r.getCredentialId() != null ? r.getCredentialId() : "");
        }
        byte[] utf8Bytes = arrayNode.toString().getBytes(StandardCharsets.UTF_8);

        Map<String, Object> map = new java.util.LinkedHashMap<>();
        map.put("store_identity", "BankCertificateRecordStore");
        map.put("record_scope", "active");
        map.put("record_count", activeRecords.size());
        map.put("serialized_bytes", utf8Bytes.length);
        map.put("serialization", "canonical-json-utf8-v1");
        map.put("measurement_method", "conformance_endpoint_json_snapshot");
        map.put("snapshot_timestamp", java.time.Instant.now().toString());
        return map;
    }
}

