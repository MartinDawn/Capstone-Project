package com.bk.research.pqc.signer;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PQCSignerApp {

    private static final Map<String, KeyPair> keyPairs = new HashMap<>();

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("Generating PQC Keys...");
        keyPairs.put("MLDSA44", generateKey("ML-DSA-44"));
        keyPairs.put("MLDSA65", generateKey("ML-DSA-65"));
        keyPairs.put("MLDSA87", generateKey("ML-DSA-87"));
        System.out.println("Keys generated successfully.");

        HttpServer server = HttpServer.create(new InetSocketAddress(8081), 0);
        server.createContext("/sign", new SignHandler());
        server.createContext("/verify", new VerifyHandler());
        server.createContext("/public-keys", new PublicKeysHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
        System.out.println("PQC Signer Server is listening on port 8081");
    }

    private static KeyPair generateKey(String alg) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
        // No initialize required for ML-DSA in BC 1.79 when using specific algorithm names
        return kpg.generateKeyPair();
    }

    static class SignHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try (InputStream is = exchange.getRequestBody()) {
                    String body = new String(is.readAllBytes());
                    
                    // Simple JSON parsing without dependencies
                    String dataB64 = extractJsonField(body, "data");
                    String alg = extractJsonField(body, "pqcAlg");
                    
                    if (dataB64 == null || alg == null) {
                        sendResponse(exchange, 400, "{\"error\": \"Missing data or pqcAlg\"}");
                        return;
                    }

                    if (!keyPairs.containsKey(alg)) {
                        sendResponse(exchange, 400, "{\"error\": \"Unsupported algorithm\"}");
                        return;
                    }

                    byte[] data = Base64.getDecoder().decode(dataB64);
                    Signature signer = Signature.getInstance("ML-DSA", "BC");
                    signer.initSign(keyPairs.get(alg).getPrivate());
                    signer.update(data);
                    byte[] sigBytes = signer.sign();

                    String sigB64 = Base64.getEncoder().encodeToString(sigBytes);
                    sendResponse(exchange, 200, "{\"signature\": \"" + sigB64 + "\"}");

                } catch (Exception e) {
                    e.printStackTrace();
                    sendResponse(exchange, 500, "{\"error\": \"" + e.getMessage() + "\"}");
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
            }
        }

        private String extractJsonField(String json, String field) {
            String search = "\"" + field + "\":";
            int idx = json.indexOf(search);
            if (idx == -1) return null;
            idx += search.length();
            int startQuote = json.indexOf("\"", idx);
            if (startQuote == -1) return null;
            int endQuote = json.indexOf("\"", startQuote + 1);
            if (endQuote == -1) return null;
            return json.substring(startQuote + 1, endQuote);
        }

        private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] bytes = response.getBytes();
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                try (InputStream is = exchange.getRequestBody()) {
                    String body = new String(is.readAllBytes());
                    
                    String dataB64 = extractJsonField(body, "data");
                    String sigB64 = extractJsonField(body, "signature");
                    String alg = extractJsonField(body, "pqcAlg");
                    String pubKeyB64 = extractJsonField(body, "publicKey");
                    
                    if (dataB64 == null || sigB64 == null || alg == null || pubKeyB64 == null) {
                        sendResponse(exchange, 400, "{\"error\": \"Missing parameters\"}");
                        return;
                    }

                    byte[] data = Base64.getDecoder().decode(dataB64);
                    byte[] sigBytes = Base64.getDecoder().decode(sigB64);
                    byte[] pubKeyBytes = Base64.getDecoder().decode(pubKeyB64);
                    
                    PublicKey pqcPublicKey;
                    Signature verifier;
                    if (alg.contains("MLDSA65-ECDSA") || alg.contains("Composite")) {
                        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("MLDSA65-ECDSA-P384-SHA512", "BC");
                        pqcPublicKey = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(pubKeyBytes));
                        verifier = Signature.getInstance("MLDSA65-ECDSA-P384-SHA512", "BC");
                    } else {
                        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("ML-DSA", "BC");
                        pqcPublicKey = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(pubKeyBytes));
                        String bcAlgName = alg.replace("MLDSA", "ML-DSA-");
                        verifier = Signature.getInstance(bcAlgName, "BC");
                    }
                    verifier.initVerify(pqcPublicKey);
                    verifier.update(data);
                    boolean isValid = verifier.verify(sigBytes);

                    sendResponse(exchange, 200, "{\"valid\": " + isValid + "}");

                } catch (Exception e) {
                    e.printStackTrace();
                    sendResponse(exchange, 500, "{\"error\": \"" + e.getMessage() + "\"}");
                }
            } else {
                sendResponse(exchange, 405, "{\"error\": \"Method not allowed\"}");
            }
        }

        private String extractJsonField(String json, String field) {
            String search = "\"" + field + "\":";
            int idx = json.indexOf(search);
            if (idx == -1) return null;
            idx += search.length();
            int startQuote = json.indexOf("\"", idx);
            if (startQuote == -1) return null;
            int endQuote = json.indexOf("\"", startQuote + 1);
            if (endQuote == -1) return null;
            return json.substring(startQuote + 1, endQuote);
        }

        private void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            byte[] bytes = response.getBytes();
            exchange.sendResponseHeaders(statusCode, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    static class PublicKeysHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("GET".equals(exchange.getRequestMethod())) {
                StringBuilder json = new StringBuilder("{");
                boolean first = true;
                for (Map.Entry<String, KeyPair> entry : keyPairs.entrySet()) {
                    if (!first) json.append(",");
                    json.append("\"").append(entry.getKey()).append("\":\"");
                    json.append(Base64.getEncoder().encodeToString(entry.getValue().getPublic().getEncoded()));
                    json.append("\"");
                    first = false;
                }
                json.append("}");
                
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                byte[] bytes = json.toString().getBytes();
                exchange.sendResponseHeaders(200, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } else {
                exchange.sendResponseHeaders(405, -1);
            }
        }
    }
}
