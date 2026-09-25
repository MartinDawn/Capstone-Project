package evaluation.oracle;

import java.util.*;

/**
 * Independent Reference Oracle for Decentralized Authorization Service (DAS).
 * 
 * Computes the canonical typed authority intersection across 5 input sources:
 *   SC: Service Credential boundary
 *   H:  Holder authorization
 *   R:  Resource Server constraints
 *   T:  TPP requested delegation
 *   P:  Bank Security Policy
 * 
 * Formal contract: manifests/semantic-contract.json.
 *   S_e = S_SC ∩ S_H ∩ S_R ∩ S_T ∩ S_P
 *   A_e = A_SC ∩ A_H ∩ A_R ∩ A_T ∩ A_P
 *   V_e = V_SC ∩ V_H ∩ V_R ∩ V_T ∩ V_P  where V = [t_start, t_end]
 *   D_e = D_SC ⊓ D_H ⊓ D_R ⊓ D_T ⊓ D_P  where D = (history_days, fields, page_size)
 */
public class DasOracle {

    public static class TimeInterval {
        public final long start;
        public final long end;

        public TimeInterval(long start, long end) {
            this.start = start;
            this.end = end;
        }

        public boolean isValid() {
            return start <= end;
        }

        public TimeInterval intersect(TimeInterval other) {
            if (other == null) return this;
            return new TimeInterval(Math.max(this.start, other.start), Math.min(this.end, other.end));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TimeInterval that = (TimeInterval) o;
            return start == that.start && end == that.end;
        }

        @Override
        public int hashCode() {
            return Objects.hash(start, end);
        }

        @Override
        public String toString() {
            return "[" + start + ", " + end + "]";
        }
    }

    public static class DataPredicate {
        public final int historyWindowDays;
        public final Set<String> fields;
        public final int maxPageSize;

        public DataPredicate(int historyWindowDays, Set<String> fields, int maxPageSize) {
            this.historyWindowDays = historyWindowDays;
            this.fields = Collections.unmodifiableSet(new TreeSet<>(fields != null ? fields : Collections.emptySet()));
            this.maxPageSize = maxPageSize;
        }

        public boolean isValid() {
            return historyWindowDays > 0 && maxPageSize > 0 && !fields.isEmpty();
        }

        public DataPredicate meet(DataPredicate other) {
            if (other == null) return this;
            int h = Math.min(this.historyWindowDays, other.historyWindowDays);
            int p = Math.min(this.maxPageSize, other.maxPageSize);
            Set<String> f = new TreeSet<>(this.fields);
            f.retainAll(other.fields);
            return new DataPredicate(h, f, p);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            DataPredicate that = (DataPredicate) o;
            return historyWindowDays == that.historyWindowDays &&
                    maxPageSize == that.maxPageSize &&
                    Objects.equals(fields, that.fields);
        }

        @Override
        public int hashCode() {
            return Objects.hash(historyWindowDays, fields, maxPageSize);
        }

        @Override
        public String toString() {
            return "DataPredicate{historyDays=" + historyWindowDays +
                    ", fields=" + fields +
                    ", pageSize=" + maxPageSize + '}';
        }
    }

    public static class AuthorityVector {
        public final Set<String> services;        // S dimension
        public final Set<String> accounts;        // A dimension
        public final TimeInterval validity;       // V dimension
        public final DataPredicate dataPredicate; // D dimension

        public AuthorityVector(Set<String> services, Set<String> accounts, TimeInterval validity, DataPredicate dataPredicate) {
            this.services = Collections.unmodifiableSet(new TreeSet<>(services != null ? services : Collections.emptySet()));
            this.accounts = Collections.unmodifiableSet(new TreeSet<>(accounts != null ? accounts : Collections.emptySet()));
            this.validity = validity != null ? validity : new TimeInterval(0, 0);
            this.dataPredicate = dataPredicate != null ? dataPredicate : new DataPredicate(0, Collections.emptySet(), 0);
        }

        // Backward compatibility constructor
        public AuthorityVector(Set<String> services, Set<String> accounts, TimeInterval validity, Set<String> fieldsOnly) {
            this(services, accounts, validity, new DataPredicate(30, fieldsOnly, 25));
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthorityVector that = (AuthorityVector) o;
            return Objects.equals(services, that.services) &&
                   Objects.equals(accounts, that.accounts) &&
                   Objects.equals(validity, that.validity) &&
                   Objects.equals(dataPredicate, that.dataPredicate);
        }

        @Override
        public int hashCode() {
            return Objects.hash(services, accounts, validity, dataPredicate);
        }

        @Override
        public String toString() {
            return "AuthorityVector{" +
                    "S=" + services +
                    ", A=" + accounts +
                    ", V=" + validity +
                    ", D=" + dataPredicate +
                    '}';
        }
    }

    public static class DecisionResult {
        public final boolean permitted;
        public final AuthorityVector effectiveAuthority;
        public final String reason;

        public DecisionResult(boolean permitted, AuthorityVector effectiveAuthority, String reason) {
            this.permitted = permitted;
            this.effectiveAuthority = effectiveAuthority;
            this.reason = reason;
        }

        public static DecisionResult permit(AuthorityVector effective) {
            return new DecisionResult(true, effective, "PERMIT");
        }

        public static DecisionResult deny(String reason) {
            return new DecisionResult(false, null, reason);
        }
    }

    public static DecisionResult evaluate(AuthorityVector sc, AuthorityVector h, AuthorityVector r, AuthorityVector t, AuthorityVector p) {
        if (sc == null || h == null || r == null || t == null || p == null) {
            return DecisionResult.deny("REJECT_NULL_INPUT_VECTOR");
        }

        // 1. S dimension: Services Intersection
        Set<String> effServices = new TreeSet<>(sc.services);
        effServices.retainAll(h.services);
        effServices.retainAll(r.services);
        effServices.retainAll(t.services);
        effServices.retainAll(p.services);
        if (effServices.isEmpty()) {
            return DecisionResult.deny("REJECT_EMPTY_SERVICES");
        }

        // 2. A dimension: Accounts Intersection
        Set<String> effAccounts = new TreeSet<>(sc.accounts);
        effAccounts.retainAll(h.accounts);
        effAccounts.retainAll(r.accounts);
        effAccounts.retainAll(t.accounts);
        effAccounts.retainAll(p.accounts);
        if (effAccounts.isEmpty()) {
            return DecisionResult.deny("REJECT_EMPTY_ACCOUNTS");
        }

        // 3. V dimension: Validity Intersection
        TimeInterval effValidity = sc.validity
                .intersect(h.validity)
                .intersect(r.validity)
                .intersect(t.validity)
                .intersect(p.validity);
        if (!effValidity.isValid()) {
            return DecisionResult.deny("REJECT_INVALID_VALIDITY_INTERVAL");
        }

        // 4. D dimension: Data Predicate Meet
        DataPredicate effData = sc.dataPredicate
                .meet(h.dataPredicate)
                .meet(r.dataPredicate)
                .meet(t.dataPredicate)
                .meet(p.dataPredicate);
        if (effData.fields.isEmpty()) {
            return DecisionResult.deny("REJECT_EMPTY_DATA_FIELDS");
        }
        if (effData.historyWindowDays <= 0) {
            return DecisionResult.deny("REJECT_INVALID_HISTORY_WINDOW");
        }
        if (effData.maxPageSize <= 0) {
            return DecisionResult.deny("REJECT_INVALID_PAGE_SIZE");
        }

        AuthorityVector effective = new AuthorityVector(effServices, effAccounts, effValidity, effData);
        return DecisionResult.permit(effective);
    }

    public static void main(String[] args) {
        System.out.println("=== Testing VDAM Independent DAS Oracle (Typed S, A, V, D) ===");

        Set<String> services = new TreeSet<>(List.of("accounts", "balances", "transactions"));
        Set<String> accounts = new TreeSet<>(List.of("ACC-001", "ACC-002", "ACC-003"));
        TimeInterval validity = new TimeInterval(1788500000L, 1788600000L);
        DataPredicate data = new DataPredicate(90, new TreeSet<>(List.of("account_id", "amount", "balance", "date")), 25);

        AuthorityVector base = new AuthorityVector(services, accounts, validity, data);

        // Test 1: Identical inputs -> Permitted
        DecisionResult res1 = evaluate(base, base, base, base, base);
        assert res1.permitted : "Test 1 Failed: Expected PERMIT";
        assert res1.effectiveAuthority.equals(base) : "Test 1 Failed: Vector mismatch";
        System.out.println("Test 1 (Identical inputs): PASS -> " + res1.effectiveAuthority);

        // Test 2: Holder restricts to ACC-001 and 30 days history -> Permitted restricted
        AuthorityVector holderRestricted = new AuthorityVector(
                new TreeSet<>(List.of("accounts", "balances")),
                new TreeSet<>(List.of("ACC-001")),
                validity,
                new DataPredicate(30, new TreeSet<>(List.of("account_id", "balance")), 10)
        );
        DecisionResult res2 = evaluate(base, holderRestricted, base, base, base);
        assert res2.permitted : "Test 2 Failed: Expected PERMIT";
        assert res2.effectiveAuthority.accounts.size() == 1 : "Expected 1 account";
        assert res2.effectiveAuthority.dataPredicate.historyWindowDays == 30 : "Expected 30 days history";
        assert res2.effectiveAuthority.dataPredicate.maxPageSize == 10 : "Expected page size 10";
        System.out.println("Test 2 (Holder restriction): PASS -> " + res2.effectiveAuthority);

        // Test 3: Disjoint Accounts -> REJECT_EMPTY_ACCOUNTS
        AuthorityVector disjointAcc = new AuthorityVector(
                services,
                new TreeSet<>(List.of("ACC-999")),
                validity,
                data
        );
        DecisionResult res3 = evaluate(base, disjointAcc, base, base, base);
        assert !res3.permitted : "Test 3 Failed: Expected DENY";
        assert "REJECT_EMPTY_ACCOUNTS".equals(res3.reason) : "Expected REJECT_EMPTY_ACCOUNTS";
        System.out.println("Test 3 (Disjoint accounts rejection): PASS -> " + res3.reason);

        // Test 4: Inverted Time -> REJECT_INVALID_VALIDITY_INTERVAL
        AuthorityVector invertedTime = new AuthorityVector(
                services,
                accounts,
                new TimeInterval(1788700000L, 1788600000L),
                data
        );
        DecisionResult res4 = evaluate(base, invertedTime, base, base, base);
        assert !res4.permitted : "Test 4 Failed: Expected DENY";
        assert "REJECT_INVALID_VALIDITY_INTERVAL".equals(res4.reason) : "Expected REJECT_INVALID_VALIDITY_INTERVAL";
        System.out.println("Test 4 (Inverted time rejection): PASS -> " + res4.reason);

        // Test 5: Disjoint Fields -> REJECT_EMPTY_DATA_FIELDS
        AuthorityVector disjointFields = new AuthorityVector(
                services,
                accounts,
                validity,
                new DataPredicate(90, new TreeSet<>(List.of("non_existent_field")), 25)
        );
        DecisionResult res5 = evaluate(base, disjointFields, base, base, base);
        assert !res5.permitted : "Test 5 Failed: Expected DENY";
        assert "REJECT_EMPTY_DATA_FIELDS".equals(res5.reason) : "Expected REJECT_EMPTY_DATA_FIELDS";
        System.out.println("Test 5 (Disjoint fields rejection): PASS -> " + res5.reason);

        if (args.length > 0 && "--benchmark".equals(args[0])) {
            int iterations = 10000;
            if (args.length > 1) {
                try {
                    iterations = Integer.parseInt(args[1]);
                } catch (NumberFormatException ignored) {}
            }
            System.out.println("=== Benchmarking Independent DAS Reference Oracle (" + iterations + " evaluations) ===");
            
            // JIT warm-up
            for (int i = 0; i < 2000; i++) {
                evaluate(base, holderRestricted, base, base, base);
            }

            // Benchmark Oracle Authority Vector evaluation
            long startNs = System.nanoTime();
            int permitCount = 0;
            for (int i = 0; i < iterations; i++) {
                DecisionResult res = evaluate(base, holderRestricted, base, base, base);
                if (res.permitted) permitCount++;
            }
            long elapsedNs = System.nanoTime() - startNs;
            double totalMs = elapsedNs / 1_000_000.0;
            double usPerOp = (elapsedNs / 1000.0) / iterations;
            double opsPerSec = (iterations * 1_000_000_000.0) / elapsedNs;

            // Measure Collector Telemetry Overhead (System.nanoTime sampling)
            int timerIterations = 1_000_000;
            long timerStartNs = System.nanoTime();
            long dummySum = 0;
            for (int i = 0; i < timerIterations; i++) {
                dummySum += System.nanoTime();
            }
            long timerElapsedNs = System.nanoTime() - timerStartNs;
            double nsPerTimerCall = (double) timerElapsedNs / timerIterations;

            System.out.printf(Locale.US, "Oracle Evaluation: %d ops in %.2f ms | Throughput: %.1f ops/sec | Mean Latency: %.3f us/op (permits: %d)%n",
                    iterations, totalMs, opsPerSec, usPerOp, permitCount);
            System.out.printf(Locale.US, "Telemetry Collector Overhead: %.2f ns per high-res timer invocation (tested over %d calls)%n",
                    nsPerTimerCall, timerIterations);
            return;
        }

        System.out.println("All Oracle unit assertions completed successfully.");
    }
}
