package com.bk.research.pqc.bank;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/** Adds stable diagnostic fields to existing rejection responses without changing decisions. */
@ControllerAdvice
public class ConformanceErrorResponseAdvice implements ResponseBodyAdvice<Object> {
    private static final Pattern REJECTION_CODE = Pattern.compile("^(REJECT_[A-Z0-9_]+)");

    private static final Map<String, String> STAGES = Map.ofEntries(
        Map.entry("REJECT_INVALID_ROOT_VC_SIGNATURE", "root_vc_signature"),
        Map.entry("REJECT_INVALID_DELEGATION_VC_SIGNATURE", "delegation_vc_signature"),
        Map.entry("REJECT_INVALID_KB_JWT_SIGNATURE", "kb_jwt_signature"),
        Map.entry("REJECT_INVALID_VP_SIGNATURE", "vp_signature"),
        Map.entry("REJECT_INVALID_GRANT_AUDIENCE", "grant_audience"),
        Map.entry("REJECT_INVALID_KB_AUDIENCE", "kb_audience"),
        Map.entry("REJECT_NONCE_MISMATCH", "challenge_nonce"),
        Map.entry("REJECT_CORRUPTED_SD_HASH", "sd_hash"),
        Map.entry("REJECT_MISSING_ISSUANCE_RECORD", "issuance_binding_lookup"),
        Map.entry("REJECT_DISABLED_ASSOCIATION", "issuance_binding_status"),
        Map.entry("REJECT_UNAUTHORIZED_AUTHORITY_EXPANSION", "authority_containment"),
        Map.entry("REJECT_REPLAYED_CREDENTIAL", "replay_guard"),
        Map.entry("REJECT_STALE_BINDING_SNAPSHOT", "binding_snapshot_freshness"),
        Map.entry("REJECT_ROLLBACK_VERSION", "binding_version_guard"),
        Map.entry("REJECT_INVALID_DAS_ENCRYPTED_PACKAGE", "encrypted_package_integrity"),
        Map.entry("REJECT_MISSING_ROOT_VC", "root_vc_structure"),
        Map.entry("REJECT_MALFORMED_ROOT_VC", "root_vc_structure"),
        Map.entry("REJECT_UNTRUSTED_ROOT_VC_ISSUER", "root_vc_issuer"),
        Map.entry("REJECT_REVOKED_OR_EXPIRED_CREDENTIAL", "credential_lifecycle"),
        Map.entry("REJECT_MISSING_DELEGATION_VC", "delegation_vc_structure"),
        Map.entry("REJECT_MALFORMED_DELEGATION_VC", "delegation_vc_structure"),
        Map.entry("REJECT_WRONG_DELEGATION_SIGNER", "delegation_signer_binding"),
        Map.entry("REJECT_MISMATCHED_ISSUANCE_RECORD", "issuance_lineage_binding"),
        Map.entry("REJECT_MALFORMED_KB_JWT", "kb_jwt_structure"),
        Map.entry("REJECT_INVALID_KB_JWT", "kb_jwt_validation"),
        Map.entry("REJECT_SUBSTITUTED_HOLDER_KEY", "holder_key_binding"),
        Map.entry("REJECT_PRESENTER_CERTIFICATE_MISMATCH", "presenter_certificate_binding"),
        Map.entry("REJECT_DAS_ENCRYPTED_PACKAGE_MISMATCH", "encrypted_package_binding")
    );

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request, ServerHttpResponse response) {
        if (!(body instanceof Map<?, ?> original)) {
            return body;
        }
        Object descriptionValue = original.get("error_description");
        if (!(descriptionValue instanceof String description)) {
            return body;
        }
        Matcher matcher = REJECTION_CODE.matcher(description);
        if (!matcher.find()) {
            return body;
        }
        String code = matcher.group(1);
        Map<Object, Object> enriched = new LinkedHashMap<>(original);
        enriched.putIfAbsent("error_code", code);
        enriched.putIfAbsent("verification_stage", STAGES.getOrDefault(code, "unspecified_security_boundary"));
        return enriched;
    }
}
