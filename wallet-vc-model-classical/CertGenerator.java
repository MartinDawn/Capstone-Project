import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Base64;

public class CertGenerator {

    private static void savePem(String filepath, String type, byte[] data) throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(data);
        sb.append(b64).append("\n");
        sb.append("-----END ").append(type).append("-----\n");
        try (FileWriter fw = new FileWriter(filepath)) {
            fw.write(sb.toString());
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("============================================================");
            System.out.println("Generating Classical ECDSA P-384 Certificates (CA Signed)");
            System.out.println("============================================================");

            String baseDir = System.getProperty("user.dir");
            String bankCerts = baseDir + "/bank/tls-proxy/certs";
            String walletCerts = baseDir + "/wallet/tls-proxy/certs";
            String tppCerts = baseDir + "/tpp/tls-proxy/certs";
            String authCerts = baseDir + "/bank/auth_server/certs";

            new File(bankCerts).mkdirs();
            new File(walletCerts).mkdirs();
            new File(tppCerts).mkdirs();
            new File(authCerts).mkdirs();

            String ksFile = bankCerts + "/temp-keystore.p12";
            String pass = "password";

            // Delete old temp keystore if any
            new File(ksFile).delete();

            // 1. Generate Root CA
            System.out.println(">> [1/6] Generating ECDSA P-384 Root CA...");
            runKeytool("-genkeypair -alias ca -keyalg EC -groupname secp384r1 -sigalg SHA384withECDSA -validity 3650 -keystore " + ksFile + " -storepass " + pass + " -storetype PKCS12 -dname \"CN=Classical ECDSA Root CA, O=BK Research, C=VN\" -ext BasicConstraints:critical=ca:true -ext KeyUsage:critical=keyCertSign,cRLSign");

            // 2. Generate Server Cert for tls-server-proxy
            System.out.println(">> [2/6] Generating and Signing Server Certificate for tls-server-proxy...");
            runKeytool("-genkeypair -alias server -keyalg EC -groupname secp384r1 -sigalg SHA384withECDSA -validity 365 -keystore " + ksFile + " -storepass " + pass + " -storetype PKCS12 -dname \"CN=tls-server-proxy, O=BK Research, C=VN\"");
            String serverCsr = bankCerts + "/server.csr";
            runKeytool("-certreq -alias server -keystore " + ksFile + " -storepass " + pass + " -file " + serverCsr);
            runKeytool("-gencert -alias ca -infile " + serverCsr + " -outfile " + bankCerts + "/server.crt -rfc -keystore " + ksFile + " -storepass " + pass + " -validity 365 -sigalg SHA384withECDSA -ext SAN=dns:tls-server-proxy,dns:localhost,ip:127.0.0.1 -ext KeyUsage=digitalSignature,keyEncipherment,keyAgreement -ext ExtendedKeyUsage=serverAuth,clientAuth");
            new File(serverCsr).delete();

            // 3. Generate Wallet Client Cert
            System.out.println(">> [3/6] Generating and Signing Client Certificate for Wallet...");
            runKeytool("-genkeypair -alias wallet -keyalg EC -groupname secp384r1 -sigalg SHA384withECDSA -validity 365 -keystore " + ksFile + " -storepass " + pass + " -storetype PKCS12 -dname \"CN=Classical Wallet Client, O=BK Research, C=VN\"");
            String walletCsr = bankCerts + "/wallet.csr";
            runKeytool("-certreq -alias wallet -keystore " + ksFile + " -storepass " + pass + " -file " + walletCsr);
            runKeytool("-gencert -alias ca -infile " + walletCsr + " -outfile " + bankCerts + "/wallet.crt -rfc -keystore " + ksFile + " -storepass " + pass + " -validity 365 -sigalg SHA384withECDSA -ext KeyUsage=digitalSignature,keyAgreement -ext ExtendedKeyUsage=clientAuth");
            new File(walletCsr).delete();

            // 4. Generate TPP Client Cert
            System.out.println(">> [4/6] Generating and Signing Client Certificate for TPP...");
            runKeytool("-genkeypair -alias tpp -keyalg EC -groupname secp384r1 -sigalg SHA384withECDSA -validity 365 -keystore " + ksFile + " -storepass " + pass + " -storetype PKCS12 -dname \"CN=Classical TPP Client, O=BK Research, C=VN\"");
            String tppCsr = bankCerts + "/tpp.csr";
            runKeytool("-certreq -alias tpp -keystore " + ksFile + " -storepass " + pass + " -file " + tppCsr);
            runKeytool("-gencert -alias ca -infile " + tppCsr + " -outfile " + bankCerts + "/tpp.crt -rfc -keystore " + ksFile + " -storepass " + pass + " -validity 365 -sigalg SHA384withECDSA -ext KeyUsage=digitalSignature,keyAgreement -ext ExtendedKeyUsage=clientAuth");
            new File(tppCsr).delete();

            // 5. Generate Wallet Inbound Server Cert
            System.out.println(">> [5/6] Generating and Signing Server Certificate for tls-wallet-inbound...");
            runKeytool("-genkeypair -alias walletinbound -keyalg EC -groupname secp384r1 -sigalg SHA384withECDSA -validity 365 -keystore " + ksFile + " -storepass " + pass + " -storetype PKCS12 -dname \"CN=tls-wallet-inbound, O=BK Research, C=VN\"");
            String walletInboundCsr = bankCerts + "/wallet-inbound.csr";
            runKeytool("-certreq -alias walletinbound -keystore " + ksFile + " -storepass " + pass + " -file " + walletInboundCsr);
            runKeytool("-gencert -alias ca -infile " + walletInboundCsr + " -outfile " + bankCerts + "/wallet-inbound.crt -rfc -keystore " + ksFile + " -storepass " + pass + " -validity 365 -sigalg SHA384withECDSA -ext SAN=dns:tls-wallet-inbound,dns:localhost,ip:127.0.0.1 -ext KeyUsage=digitalSignature,keyEncipherment,keyAgreement -ext ExtendedKeyUsage=serverAuth,clientAuth");
            new File(walletInboundCsr).delete();

            // 6. Generate Browser RSA Cert (self-signed for browser proxy)
            System.out.println(">> [6/6] Generating Browser RSA Certificate...");
            runKeytool("-genkeypair -alias browser -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 -keystore " + ksFile + " -storepass " + pass + " -storetype PKCS12 -dname \"CN=localhost, O=BK Research, C=VN\"");

            // Export Root CA cert
            runKeytool("-exportcert -rfc -alias ca -keystore " + ksFile + " -storepass " + pass + " -file " + bankCerts + "/ca.crt");

            // Load PKCS12 and export Private Keys and browser cert
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (var is = Files.newInputStream(Paths.get(ksFile))) {
                ks.load(is, pass.toCharArray());
            }

            exportKey(ks, "ca", bankCerts + "/ca.key");
            exportKey(ks, "server", bankCerts + "/server.key");
            exportKey(ks, "wallet", bankCerts + "/wallet.key");
            exportKey(ks, "tpp", bankCerts + "/tpp.key");
            exportKey(ks, "walletinbound", bankCerts + "/wallet-inbound.key");

            Certificate browserCert = ks.getCertificate("browser");
            savePem(bankCerts + "/browser.crt", "CERTIFICATE", browserCert.getEncoded());
            exportKey(ks, "browser", bankCerts + "/browser.key");

            new File(ksFile).delete();

            // Distribute to all directories
            System.out.println(">> Distributing CA-signed certificates to Wallet, TPP, and Bank Auth Server...");
            copyFile(bankCerts + "/ca.crt", walletCerts + "/ca.crt");
            copyFile(bankCerts + "/wallet.crt", walletCerts + "/wallet.crt");
            copyFile(bankCerts + "/wallet.key", walletCerts + "/wallet.key");
            copyFile(bankCerts + "/wallet-inbound.crt", walletCerts + "/wallet-inbound.crt");
            copyFile(bankCerts + "/wallet-inbound.key", walletCerts + "/wallet-inbound.key");
            copyFile(bankCerts + "/browser.crt", walletCerts + "/browser.crt");
            copyFile(bankCerts + "/browser.key", walletCerts + "/browser.key");

            copyFile(bankCerts + "/ca.crt", tppCerts + "/ca.crt");
            copyFile(bankCerts + "/tpp.crt", tppCerts + "/tpp.crt");
            copyFile(bankCerts + "/tpp.key", tppCerts + "/tpp.key");
            copyFile(bankCerts + "/browser.crt", tppCerts + "/browser.crt");
            copyFile(bankCerts + "/browser.key", tppCerts + "/browser.key");

            copyFile(bankCerts + "/ca.crt", authCerts + "/ca.crt");
            copyFile(bankCerts + "/server.crt", authCerts + "/server.crt");
            copyFile(bankCerts + "/server.key", authCerts + "/server.key");

            System.out.println("============================================================");
            System.out.println("All CA-signed certificates generated & distributed successfully!");
            System.out.println("============================================================");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void exportKey(KeyStore ks, String alias, String keyPath) throws Exception {
        Key key = ks.getKey(alias, "password".toCharArray());
        savePem(keyPath, "PRIVATE KEY", key.getEncoded());
    }

    private static void copyFile(String src, String dst) throws Exception {
        Files.copy(Paths.get(src), Paths.get(dst), StandardCopyOption.REPLACE_EXISTING);
    }

    private static void runKeytool(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec("keytool " + cmd);
        int exit = p.waitFor();
        if (exit != 0) {
            byte[] err = p.getErrorStream().readAllBytes();
            throw new RuntimeException("keytool failed: " + new String(err));
        }
    }
}
