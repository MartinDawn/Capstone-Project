package com.bk.research.pqc.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Fail-closed S/A/V/D meet shared by the hybrid token path. */
@Service
public class TypedAuthorityService {
    private final ObjectMapper mapper = new ObjectMapper();
    private volatile JsonNode policyAuthority;
    @Value("${TYPED_AUTHORITY_EVALUATION_TIME:0}")
    private long configuredEvaluationTime;

    public static final class Decision {
        private final boolean permitted;
        private final String reason;
        private final ObjectNode authority;
        private Decision(boolean permitted, String reason, ObjectNode authority) {
            this.permitted = permitted;
            this.reason = reason;
            this.authority = authority;
        }
        public boolean isPermitted() { return permitted; }
        public String getReason() { return reason; }
        public ObjectNode getAuthority() { return authority; }
    }

    public synchronized void setPolicyAuthority(JsonNode authority) {
        validateShape(authority, "P");
        policyAuthority = authority.deepCopy();
    }
    public JsonNode getPolicyAuthority() {
        JsonNode current = policyAuthority;
        return current == null ? null : current.deepCopy();
    }
    public synchronized void setConfiguredEvaluationTime(long configuredEvaluationTime) {
        this.configuredEvaluationTime = configuredEvaluationTime;
    }
    public long getEvaluationTime() { return configuredEvaluationTime > 0 ? configuredEvaluationTime : System.currentTimeMillis() / 1000; }

    public Decision evaluate(JsonNode sc, JsonNode h, JsonNode r, JsonNode t) {
        JsonNode p = policyAuthority;
        if (p == null) return deny("REJECT_MISSING_POLICY_AUTHORITY");
        validateShape(sc, "SC"); validateShape(h, "H"); validateShape(r, "R"); validateShape(t, "T"); validateShape(p, "P");
        List<JsonNode> inputs = List.of(sc, h, r, t, p);
        Set<String> services = intersection(inputs, "services");
        if (services.isEmpty()) return deny("REJECT_EMPTY_SERVICES");
        Set<String> accounts = intersection(inputs, "accounts");
        if (accounts.isEmpty()) return deny("REJECT_EMPTY_ACCOUNTS");
        long start = inputs.stream().mapToLong(v -> v.path("validity").path("start").asLong()).max().orElseThrow();
        long end = inputs.stream().mapToLong(v -> v.path("validity").path("end").asLong()).min().orElseThrow();
        if (start > end) return deny("REJECT_INVALID_VALIDITY_INTERVAL");
        long evaluationTime = getEvaluationTime();
        if (configuredEvaluationTime > 0 && (evaluationTime < start || evaluationTime > end)) return deny("REJECT_AUTHORITY_NOT_CURRENT");
        long historyDays = inputs.stream().mapToLong(v -> v.path("data").path("history_days").asLong()).min().orElseThrow();
        if (historyDays <= 0) return deny("REJECT_INVALID_HISTORY_WINDOW");
        Set<String> fields = intersection(inputs, "data", "fields");
        if (fields.isEmpty()) return deny("REJECT_EMPTY_DATA_FIELDS");
        long pageSize = inputs.stream().mapToLong(v -> v.path("data").path("page_size").asLong()).min().orElseThrow();
        if (pageSize <= 0) return deny("REJECT_INVALID_PAGE_SIZE");
        ObjectNode effective = mapper.createObjectNode();
        putSorted(effective.putArray("services"), services);
        putSorted(effective.putArray("accounts"), accounts);
        ObjectNode validity = effective.putObject("validity"); validity.put("start", start); validity.put("end", end);
        ObjectNode data = effective.putObject("data"); data.put("history_days", historyDays); putSorted(data.putArray("fields"), fields); data.put("page_size", pageSize);
        return new Decision(true, "PERMIT", effective);
    }

    private Decision deny(String reason) { return new Decision(false, reason, null); }
    private void validateShape(JsonNode authority, String source) {
        if (authority == null || !authority.isObject() || !isNonEmptyArray(authority.get("services"))
                || !isNonEmptyArray(authority.get("accounts")) || !authority.path("validity").path("start").canConvertToLong()
                || !authority.path("validity").path("end").canConvertToLong() || !authority.path("data").path("history_days").canConvertToLong()
                || !isNonEmptyArray(authority.path("data").get("fields")) || !authority.path("data").path("page_size").canConvertToLong()) {
            throw new IllegalArgumentException("REJECT_MALFORMED_TYPED_AUTHORITY_" + source);
        }
    }
    private boolean isNonEmptyArray(JsonNode node) { return node != null && node.isArray() && !node.isEmpty(); }
    private Set<String> intersection(List<JsonNode> inputs, String... path) {
        Set<String> result = null;
        for (JsonNode input : inputs) {
            JsonNode node = input; for (String part : path) node = node.path(part);
            Set<String> values = new LinkedHashSet<>(); node.forEach(value -> values.add(value.asText()));
            if (result == null) result = values; else result.retainAll(values);
        }
        return result == null ? Collections.emptySet() : result;
    }
    private void putSorted(ArrayNode target, Set<String> values) {
        List<String> sorted = new ArrayList<>(values); Collections.sort(sorted); sorted.forEach(target::add);
    }
}
