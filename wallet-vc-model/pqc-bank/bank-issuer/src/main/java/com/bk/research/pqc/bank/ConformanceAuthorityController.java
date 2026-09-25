package com.bk.research.pqc.bank;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@Profile("conformance")
@RequestMapping("/api/test/typed-authority")
public class ConformanceAuthorityController {
    private final TypedAuthorityService authorityService;
    public ConformanceAuthorityController(TypedAuthorityService authorityService) { this.authorityService = authorityService; }
    @PostMapping("/policy")
    public ResponseEntity<?> setPolicy(@RequestBody JsonNode policy) {
        authorityService.setPolicyAuthority(policy);
        if (policy.has("evaluation_time")) {
            authorityService.setConfiguredEvaluationTime(policy.get("evaluation_time").asLong());
        } else {
            authorityService.setConfiguredEvaluationTime(0L);
        }
        return ResponseEntity.ok(Map.of("policy_authority", authorityService.getPolicyAuthority()));
    }
    @GetMapping("/policy")
    public ResponseEntity<?> getPolicy() {
        JsonNode policy = authorityService.getPolicyAuthority();
        if (policy == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(Map.of("policy_authority", policy));
    }
}
