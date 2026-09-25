package com.bk.research.classical.bank;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class PolicyService {

    private final ObjectMapper mapper = new ObjectMapper();
    private long version = 3;
    private final Set<String> masterScopeCatalog = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<String> masterIdentityClaims = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Map<String, Set<String>> accountTypeEntitlements = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> tppMaxScopes = new ConcurrentHashMap<>();
    private final Map<String, String> tppStatusMap = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        loadPolicy();
    }

    public synchronized void loadPolicy() {
        try {
            ClassPathResource resource = new ClassPathResource("authorization-policy.json");
            if (resource.exists()) {
                try (InputStream is = resource.getInputStream()) {
                    JsonNode root = mapper.readTree(is);
                    if (root.has("version")) {
                        this.version = root.get("version").asLong();
                    }

                    masterScopeCatalog.clear();
                    if (root.has("master_scope_catalog") && root.get("master_scope_catalog").isArray()) {
                        for (JsonNode s : root.get("master_scope_catalog")) {
                            masterScopeCatalog.add(s.asText());
                        }
                    }

                    masterIdentityClaims.clear();
                    if (root.has("master_identity_claims") && root.get("master_identity_claims").isArray()) {
                        for (JsonNode c : root.get("master_identity_claims")) {
                            masterIdentityClaims.add(c.asText());
                        }
                    }

                    accountTypeEntitlements.clear();
                    if (root.has("account_type_entitlements")) {
                        JsonNode accNode = root.get("account_type_entitlements");
                        Iterator<Map.Entry<String, JsonNode>> fields = accNode.fields();
                        while (fields.hasNext()) {
                            Map.Entry<String, JsonNode> entry = fields.next();
                            String type = entry.getKey();
                            Set<String> scopes = new HashSet<>();
                            if (entry.getValue().isArray()) {
                                for (JsonNode sc : entry.getValue()) {
                                    scopes.add(sc.asText());
                                }
                            }
                            accountTypeEntitlements.put(type, scopes);
                        }
                    }

                    tppMaxScopes.clear();
                    tppStatusMap.clear();
                    if (root.has("registered_tpps")) {
                        JsonNode tpps = root.get("registered_tpps");
                        Iterator<Map.Entry<String, JsonNode>> fields = tpps.fields();
                        while (fields.hasNext()) {
                            Map.Entry<String, JsonNode> entry = fields.next();
                            String clientId = entry.getKey();
                            JsonNode tppInfo = entry.getValue();

                            String status = tppInfo.has("status") ? tppInfo.get("status").asText() : "ACTIVE";
                            tppStatusMap.put(clientId, status);

                            Set<String> scopes = new HashSet<>();
                            if (tppInfo.has("max_scopes") && tppInfo.get("max_scopes").isArray()) {
                                for (JsonNode sc : tppInfo.get("max_scopes")) {
                                    scopes.add(sc.asText());
                                }
                            }
                            tppMaxScopes.put(clientId, scopes);
                        }
                    }
                    System.out.println("[PolicyService] Classical Policy Engine initialized. Version: " + version + ", Master Scope Count: " + masterScopeCatalog.size());
                }
            } else {
                System.err.println("[PolicyService] authorization-policy.json not found, using default master policy.");
                useDefaults();
            }
        } catch (Exception e) {
            System.err.println("[PolicyService] Error loading policy: " + e.getMessage() + ". Using defaults.");
            useDefaults();
        }
    }

    private void useDefaults() {
        masterScopeCatalog.addAll(Arrays.asList(
            "accounts:read", "transfers:read", "transfers:write", "profile:read", "transactions:read",
            "ReadAccountsBasic", "ReadAccountsDetail", "ReadBalances", "ReadTransactionsBasic", "ReadTransactionsDetail", "ReadTransactionsCredits", "ReadTransactionsDebits", "CreateDomesticPayment"
        ));
        accountTypeEntitlements.put("REGULAR_USER", new HashSet<>(Arrays.asList(
            "accounts:read", "transfers:read", "transfers:write", "profile:read", "transactions:read",
            "ReadAccountsBasic", "ReadAccountsDetail", "ReadBalances", "ReadTransactionsBasic", "ReadTransactionsDetail", "ReadTransactionsCredits", "ReadTransactionsDebits", "CreateDomesticPayment"
        )));
        tppStatusMap.put("tpp-demo-client", "ACTIVE");
        tppMaxScopes.put("tpp-demo-client", new HashSet<>(Arrays.asList(
            "accounts:read", "transfers:read", "transfers:write", "profile:read", "transactions:read",
            "ReadAccountsBasic", "ReadAccountsDetail", "ReadBalances", "ReadTransactionsBasic", "ReadTransactionsDetail", "ReadTransactionsCredits", "ReadTransactionsDebits", "CreateDomesticPayment"
        )));
    }

    public long getVersion() {
        return version;
    }

    public Set<String> getMasterScopeCatalog() {
        return Collections.unmodifiableSet(masterScopeCatalog);
    }

    public Set<String> getMasterIdentityClaims() {
        if (masterIdentityClaims.isEmpty()) {
            return new LinkedHashSet<>(Arrays.asList("name", "email", "dob", "nationalId", "address", "phoneNumber"));
        }
        return Collections.unmodifiableSet(masterIdentityClaims);
    }

    public Set<String> getEntitledScopesForUser(String accountType) {
        String typeKey = (accountType != null && accountTypeEntitlements.containsKey(accountType.toUpperCase()))
            ? accountType.toUpperCase() : "REGULAR_USER";
        
        Set<String> userAllowed = accountTypeEntitlements.getOrDefault(typeKey, masterScopeCatalog);
        Set<String> result = new HashSet<>(userAllowed);
        result.retainAll(masterScopeCatalog);
        return result;
    }

    public boolean isTppRegisteredAndActive(String clientId) {
        if (clientId == null) return false;
        String status = tppStatusMap.get(clientId);
        return "ACTIVE".equalsIgnoreCase(status);
    }

    public Set<String> getTppMaxScopes(String clientId) {
        return tppMaxScopes.getOrDefault(clientId, Collections.emptySet());
    }

    public Set<String> getBankPolicyScopes() {
        return Collections.unmodifiableSet(masterScopeCatalog);
    }
}
