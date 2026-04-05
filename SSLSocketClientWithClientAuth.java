// SSLSocketClientWithClientAuth.java
import java.io.*;
import java.security.*;
import javax.net.ssl.*;

public class SSLSocketClientWithClientAuth {

    public static void main(String[] args) throws Exception {
        String host = null;
        int port = -1;
        String path = null;

        // Default values for testing with ClassFileServer
        if (args.length < 3) {
            host = "localhost";
            port = 2002;
            path = "/";
            System.out.println("Using defaults: host=localhost port=2002 path=/");
        } else {
            host = args[0];
            port = Integer.parseInt(args[1]);
            path = args[2];
        }

        // Keystore contains client certificate and private key
        String keyStorePath     = System.getProperty("javax.net.ssl.keyStore",   "clientkeystore.jks");
        String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword", "clientpassword");

        // Truststore contains server's certificate (or CA cert)
        String trustStorePath     = System.getProperty("javax.net.ssl.trustStore",   "clienttruststore.jks");
        String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword", "trustpassword");

        // ── Load KeyStore (client cert + private key) ──────────────────────
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            keyStore.load(fis, keyStorePassword.toCharArray());
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, keyStorePassword.toCharArray());

        // ── Load TrustStore (trusted server cert / CA) ─────────────────────
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(trustStorePath)) {
            trustStore.load(fis, trustStorePassword.toCharArray());
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        // ── Build SSLContext ───────────────────────────────────────────────
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLSocketFactory factory = sslContext.getSocketFactory();

        // ── Connect ────────────────────────────────────────────────────────
        System.out.println("Connecting to " + host + ":" + port);
        try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {

            socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});

            // Force handshake
            socket.startHandshake();

            SSLSession session = socket.getSession();
            System.out.println("--------------------------------------");
            System.out.println("SSL Handshake successful!");
            System.out.println("Protocol    : " + session.getProtocol());
            System.out.println("Cipher Suite: " + session.getCipherSuite());
            System.out.println("Server Cert : " + session.getPeerCertificates()[0]);
            System.out.println("--------------------------------------");

            // ── Send HTTP GET ──────────────────────────────────────────────
            PrintWriter out = new PrintWriter(
                new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())));

            out.println("GET " + path + " HTTP/1.1");
            out.println("Host: " + host + ":" + port);
            out.println("User-Agent: Java/" + System.getProperty("java.version"));
            out.println("Connection: close");
            out.println();
            out.flush();

            if (out.checkError()) {
                System.out.println("ERROR: Failed to send HTTP request.");
                return;
            }

            // ── Read Response ──────────────────────────────────────────────
            BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream()));

            System.out.println("\n--- Server Response ---");
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
            System.out.println("--- End of Response ---");
        }
    }
}