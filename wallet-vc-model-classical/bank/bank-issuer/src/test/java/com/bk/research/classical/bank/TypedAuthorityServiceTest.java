package com.bk.research.classical.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

class TypedAuthorityServiceTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private TypedAuthorityService service;

    @BeforeEach
    void setUp() throws Exception {
        service = new TypedAuthorityService();
        ReflectionTestUtils.setField(service, "configuredEvaluationTime", 1789000000L);
        service.setPolicyAuthority(vector());
    }

    @Test
    void computesExactMeet() throws Exception {
        JsonNode holder = vector();
        ((com.fasterxml.jackson.databind.node.ObjectNode) holder).set("accounts", mapper.readTree("[\"ACC-001\"]"));
        TypedAuthorityService.Decision decision = service.evaluate(vector(), holder, vector(), vector());
        assertTrue(decision.isPermitted());
        assertEquals(mapper.readTree("[\"ACC-001\"]"), decision.getAuthority().get("accounts"));
    }

    @Test
    void rejectsEveryInvalidDimension() throws Exception {
        JsonNode disjointAccounts = vector();
        ((com.fasterxml.jackson.databind.node.ObjectNode) disjointAccounts).set("accounts", mapper.readTree("[\"ACC-999\"]"));
        assertEquals("REJECT_EMPTY_ACCOUNTS", service.evaluate(vector(), disjointAccounts, vector(), vector()).getReason());

        JsonNode inverted = vector();
        ((com.fasterxml.jackson.databind.node.ObjectNode) inverted.get("validity")).put("start", 1791092001L);
        assertEquals("REJECT_INVALID_VALIDITY_INTERVAL", service.evaluate(vector(), vector(), inverted, vector()).getReason());

        JsonNode disjointFields = vector();
        ((com.fasterxml.jackson.databind.node.ObjectNode) disjointFields.get("data")).set("fields", mapper.readTree("[\"merchant_category\"]"));
        assertEquals("REJECT_EMPTY_DATA_FIELDS", service.evaluate(vector(), vector(), vector(), disjointFields).getReason());

        JsonNode zeroHistory = vector();
        ((com.fasterxml.jackson.databind.node.ObjectNode) zeroHistory.get("data")).put("history_days", 0);
        assertEquals("REJECT_INVALID_HISTORY_WINDOW", service.evaluate(vector(), zeroHistory, vector(), vector()).getReason());

        JsonNode zeroPage = vector();
        ((com.fasterxml.jackson.databind.node.ObjectNode) zeroPage.get("data")).put("page_size", 0);
        service.setPolicyAuthority(zeroPage);
        assertEquals("REJECT_INVALID_PAGE_SIZE", service.evaluate(vector(), vector(), vector(), vector()).getReason());
    }

    private JsonNode vector() throws Exception {
        return mapper.readTree("""
            {"services":["accounts","balances","transactions"],
             "accounts":["ACC-001","ACC-002"],
             "validity":{"start":1788500000,"end":1791092000},
             "data":{"history_days":90,"page_size":50,
                     "fields":["account_id","amount","balance"]}}
            """);
    }
}
