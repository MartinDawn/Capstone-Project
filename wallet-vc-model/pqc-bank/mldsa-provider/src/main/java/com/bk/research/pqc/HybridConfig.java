package com.bk.research.pqc;

import java.util.logging.Logger;

public class HybridConfig {

    private static final Logger logger = Logger.getLogger(HybridConfig.class.getName());

    public enum PqcAlgorithm {
        CLASSICAL("CLASSICAL"),
        P384_MLDSA65("P384_MLDSA65"),
        HYBRID_ES384_MLDSA65("HYBRID_ES384_MLDSA65"),
        HYBRID_ES256_MLDSA65("HYBRID_ES256_MLDSA65");

        private final String value;

        PqcAlgorithm(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public static PqcAlgorithm fromString(String text) {
            if (text == null) return P384_MLDSA65;
            for (PqcAlgorithm b : PqcAlgorithm.values()) {
                if (b.value.equalsIgnoreCase(text)) {
                    return b;
                }
            }
            return P384_MLDSA65; // Default fallback
        }
        
        public boolean isHybrid() {
            return value.startsWith("HYBRID_") || value.equals("P384_MLDSA65");
        }
        
        public boolean isPqcOnly() {
            return value.startsWith("MLDSA");
        }
        
        public boolean isClassical() {
            return this == CLASSICAL;
        }

        public String getClassicalAlg() {
            if (isHybrid()) {
                if (value.contains("ES384") || value.equals("P384_MLDSA65")) return "ES384";
                if (value.contains("ES256")) return "ES256";
                if (value.contains("PS256")) return "PS256";
            }
            return "ES384";
        }

        public String getPqcAlg() {
            return "p384_mldsa65";
        }
    }

    private static PqcAlgorithm currentAlgorithm = PqcAlgorithm.P384_MLDSA65; // Default

    public static synchronized PqcAlgorithm getAlgorithm() {
        return currentAlgorithm;
    }

    public static synchronized void setAlgorithm(PqcAlgorithm alg) {
        logger.info("PQC Algorithm configured to: " + alg.getValue());
        currentAlgorithm = alg;
    }
}
