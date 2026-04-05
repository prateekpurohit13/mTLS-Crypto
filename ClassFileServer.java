// ClassFileServer.java
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.*;

public class ClassFileServer {

    private static final int    DEFAULT_PORT      = 2002;
    private static final String DEFAULT_DOCROOT   = ".";          // serve files from current dir
    private static final String KS_PATH           = "serverkeystore.jks";
    private static final String KS_PASS           = "serverpassword";
    private static final String TS_PATH           = "servertruststore.jks";
    private static final String TS_PASS           = "trustpassword";

    public static void main(String[] args) throws Exception {

        int    port    = DEFAULT_PORT;
        String docRoot = DEFAULT_DOCROOT;

        if (args.length >= 1) port    = Integer.parseInt(args[0]);
        if (args.length >= 2) docRoot = args[1];

        System.out.println("ClassFileServer starting...");
        System.out.println("Port    : " + port);
        System.out.println("DocRoot : " + new File(docRoot).getAbsolutePath());

        SSLServerSocket serverSocket = createServerSocket(port);
        System.out.println("Waiting for connections (Ctrl+C to stop)...\n");

        while (true) {
            SSLSocket client = (SSLSocket) serverSocket.accept();
    
    // Assign to final local copies before passing into lambda
    final SSLSocket finalClient = client;
    final String finalDocRoot = docRoot;
    
    new Thread(() -> handleClient(finalClient, finalDocRoot)).start();
        }
    }

    // ── Build SSL server socket requiring client auth ──────────────────────
    private static SSLServerSocket createServerSocket(int port) throws Exception {

        // Server keystore (server cert + private key)
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(KS_PATH)) {
            ks.load(fis, KS_PASS.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, KS_PASS.toCharArray());

        // Server truststore (trusted client CA / cert)
        KeyStore ts = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(TS_PATH)) {
            ts.load(fis, TS_PASS.toCharArray());
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLServerSocketFactory factory = ctx.getServerSocketFactory();
        SSLServerSocket serverSocket   = (SSLServerSocket) factory.createServerSocket(port);

        // ← This is what makes it "mutual TLS / client auth"
        serverSocket.setNeedClientAuth(true);
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});

        System.out.println("SSL Server socket created with client authentication required.");
        return serverSocket;
    }

    // ── Handle one client connection ───────────────────────────────────────
    private static void handleClient(SSLSocket client, String docRoot) {
        try {
            SSLSession session = client.getSession();
            System.out.println("Client connected : " + client.getInetAddress());
            System.out.println("Protocol         : " + session.getProtocol());
            System.out.println("Cipher Suite     : " + session.getCipherSuite());
            System.out.println("Client Cert      : " + session.getPeerCertificates()[0]);

            BufferedReader  in  = new BufferedReader(new InputStreamReader(client.getInputStream()));
            PrintWriter     out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(client.getOutputStream())));

            // Read HTTP request line
            String requestLine = in.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                client.close();
                return;
            }
            System.out.println("Request: " + requestLine);

            // Drain headers
            String header;
            while ((header = in.readLine()) != null && !header.isEmpty()) {
                System.out.println("  " + header);
            }

            // Parse path from "GET /path HTTP/1.x"
            String[] parts = requestLine.split(" ");
            String   path  = (parts.length >= 2) ? parts[1] : "/";
            if (path.equals("/")) path = "/index.html";

            File file = new File(docRoot + path);

            if (file.exists() && file.isFile()) {
                byte[] data = readFile(file);
                out.println("HTTP/1.1 200 OK");
                out.println("Content-Type: " + getMimeType(file.getName()));
                out.println("Content-Length: " + data.length);
                out.println("Connection: close");
                out.println();
                out.flush();
                client.getOutputStream().write(data);
                client.getOutputStream().flush();
                System.out.println("Served: " + file.getAbsolutePath());
            } else {
                String body = "<h1>404 Not Found</h1><p>Path: " + path + "</p>";
                out.println("HTTP/1.1 404 Not Found");
                out.println("Content-Type: text/html");
                out.println("Content-Length: " + body.length());
                out.println("Connection: close");
                out.println();
                out.print(body);
                out.flush();
                System.out.println("404: " + file.getAbsolutePath());
            }

        } catch (Exception e) {
            System.out.println("Client error: " + e.getMessage());
        } finally {
            try { client.close(); } catch (IOException ignored) {}
        }
    }

    private static byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = fis.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        }
    }

    private static String getMimeType(String name) {
        if (name.endsWith(".html") || name.endsWith(".htm")) return "text/html";
        if (name.endsWith(".class"))                          return "application/octet-stream";
        if (name.endsWith(".txt"))                            return "text/plain";
        if (name.endsWith(".jpg") || name.endsWith(".jpeg")) return "image/jpeg";
        if (name.endsWith(".png"))                            return "image/png";
        return "application/octet-stream";
    }
}