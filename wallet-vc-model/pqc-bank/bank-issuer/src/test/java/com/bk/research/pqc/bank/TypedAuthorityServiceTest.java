package com.bk.research.pqc.bank;

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
    void computesExactMeetAndRejectsEmptyAuthority() throws Exception {
        JsonNode holder = vector();
        ((com.fasterxml.jackson.databind.node.ObjectNode) holder).set("accounts", mapper.readTree("[\"ACC-001\"]"));
        TypedAuthorityService.Decision decision = service.evaluate(vector(), holder, vector(), vector());
        assertTrue(decision.isPermitted());
        assertEquals(mapper.readTree("[\"ACC-001\"]"), decision.getAuthority().get("accounts"));

        ((com.fasterxml.jackson.databind.node.ObjectNode) holder).set("accounts", mapper.readTree("[\"ACC-999\"]"));
        assertEquals("REJECT_EMPTY_ACCOUNTS", service.evaluate(vector(), holder, vector(), vector()).getReason());
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
