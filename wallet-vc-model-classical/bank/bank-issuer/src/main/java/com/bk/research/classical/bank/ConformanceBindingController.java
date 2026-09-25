package com.bk.research.classical.bank;

import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@Profile("conformance")
@RequestMapping("/api/test/bindings")
public class ConformanceBindingController {
    private final CertificateRecordStore recordStore;

    public ConformanceBindingController(CertificateRecordStore recordStore) {
        this.recordStore = recordStore;
    }

    @GetMapping("/{recordId}")
    public ResponseEntity<?> read(@PathVariable String recordId) {
        CertificateRecordStore.CertificateRecord record = recordStore.resolveCertRef(recordId);
        if (record == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(view(record));
    }

    @PostMapping("/{recordId}/status")
    public ResponseEntity<?> updateStatus(@PathVariable String recordId,
                                          @RequestBody Map<String, String> request) {
        try {
            String requestedStatus = request.get("status");
            CertificateRecordStore.Status status = CertificateRecordStore.Status.valueOf(requestedStatus);
            return ResponseEntity.ok(view(recordStore.updateStatus(recordId, status)));
        } catch (IllegalArgumentException error) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_binding_control",
                    "error_description", error.getMessage()));
        }
    }

    @PostMapping("/lookup-availability")
    public ResponseEntity<?> setLookupAvailability(@RequestBody Map<String, Object> request) {
        boolean available = request.containsKey("available") ? Boolean.parseBoolean(String.valueOf(request.get("available"))) : true;
        recordStore.setLookupAvailable(available);
        return ResponseEntity.ok(Map.of("lookup_available", available));
    }

    @PostMapping("/{recordId}/invalidate-wallet-cert")
    public ResponseEntity<?> invalidateWalletCert(@PathVariable String recordId) {
        try {
            return ResponseEntity.ok(view(recordStore.invalidateWalletCert(recordId)));
        } catch (IllegalArgumentException error) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_binding_control",
                    "error_description", error.getMessage()));
        }
    }

    @PostMapping("/{recordId}/invalidate-holder-key")
    public ResponseEntity<?> invalidateHolderKey(@PathVariable String recordId) {
        try {
            return ResponseEntity.ok(view(recordStore.invalidateHolderKey(recordId)));
        } catch (IllegalArgumentException error) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_binding_control",
                    "error_description", error.getMessage()));
        }
    }

    @PostMapping("/{recordId}/advance-version")
    public ResponseEntity<?> advanceVersion(@PathVariable String recordId) {
        try {
            return ResponseEntity.ok(view(recordStore.advanceVersion(recordId)));
        } catch (IllegalArgumentException error) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_binding_control",
                    "error_description", error.getMessage()));
        }
    }

    @PostMapping("/{recordId}/mutate")
    public ResponseEntity<?> mutateBinding(@PathVariable String recordId, @RequestBody Map<String, String> mutations) {
        try {
            return ResponseEntity.ok(view(recordStore.mutateRecord(recordId, mutations)));
        } catch (IllegalArgumentException error) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_binding_control",
                    "error_description", error.getMessage()));
        }
    }

    @PostMapping("/{recordId}/reset")
    public ResponseEntity<?> resetBinding(@PathVariable String recordId) {
        try {
            return ResponseEntity.ok(view(recordStore.resetRecord(recordId)));
        } catch (IllegalArgumentException error) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "invalid_binding_control",
                    "error_description", error.getMessage()));
        }
    }

    @GetMapping("/snapshot")
    public ResponseEntity<?> getSnapshot() {
        return ResponseEntity.ok(recordStore.getCanonicalActiveSnapshotSummary());
    }

    private Map<String, Object> view(CertificateRecordStore.CertificateRecord record) {
        Map<String, Object> map = new java.util.LinkedHashMap<>();
        map.put("record_id", record.getRecordId());
        map.put("holder_subject", record.getHolderSubject());
        map.put("wallet_certificate_thumbprint", record.getCertThumbprint());
        map.put("status", record.getStatus().name());
        map.put("binding_version", record.getAuditVersion());
        map.put("wallet_cert_invalidated", record.isWalletCertInvalidated());
        map.put("holder_key_invalidated", record.isHolderKeyInvalidated());
        map.put("holder_jwk", record.getRawJwkJson() != null ? record.getRawJwkJson() : "");
        map.put("created_at", record.getCreatedAt());
        return map;
    }
}
