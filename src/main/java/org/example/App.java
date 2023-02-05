package org.example;

import javax.net.ssl.*;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class App {

    private final String trustStorePath;
    private final char[] trustStorePassword;
    private final String trustStoreType;

    public App() {
        trustStorePath = "";
        trustStorePassword = "".toCharArray();
        trustStoreType = "";
    }

    public App(String trustStorePath, char[] trustStorePassword, String trustStoreType) {
        this.trustStorePath = trustStorePath;
        this.trustStorePassword = trustStorePassword;
        this.trustStoreType = trustStoreType;
    }

    private TrustManager[] getCustomTrustStoreWithDefaultCerts(String[] certs) throws Exception {
        KeyStore keyStore = getKeyStoreWithCustomCerts(certs);

        TrustManagerFactory jdkDefaultTrustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        jdkDefaultTrustManagerFactory.init((KeyStore) null);

        List<TrustManager> trustManagers = Arrays.asList(jdkDefaultTrustManagerFactory.getTrustManagers());

        List<X509Certificate> certificates = trustManagers.stream()
                .filter(X509TrustManager.class::isInstance)
                .map(X509TrustManager.class::cast)
                .map(trustManager -> Arrays.asList(trustManager.getAcceptedIssuers()))
                .flatMap(Collection::stream)
                .collect(Collectors.toList());
        for (X509Certificate certificate : certificates) {
            keyStore.setCertificateEntry(String.valueOf(certificate.getSerialNumber()), certificate);
        }
        keyStore.store(new FileOutputStream(trustStorePath), trustStorePassword);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return trustManagerFactory.getTrustManagers();
    }

    public void setCustomTrustStoreInSSLContext(String[] certs) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(new KeyManager[0], getTrustManagerWithCustomCert(certs), new SecureRandom());
            SSLContext.setDefault(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setCustomTrustStoreWithDefaultCertsInSSLContext(String[] certs) {
        try {
            SSLContext context = SSLContext.getInstance("TLSv1.3");
            context.init(new KeyManager[0], getCustomTrustStoreWithDefaultCerts(certs), new SecureRandom());

            SSLContext.setDefault(context);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private TrustManager[] getTrustManagerWithCustomCert(String[] certs) throws Exception {
        KeyStore keyStore = getKeyStoreWithCustomCerts(certs);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return trustManagerFactory.getTrustManagers();
    }

    private KeyStore getKeyStoreWithCustomCerts(String[] certs) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(trustStoreType);
        keyStore.load(null, null);
        for (String certFile : certs) {
            try (FileInputStream fileInputStream = new FileInputStream(certFile);
                 BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream)
            ) {
                while (bufferedInputStream.available() > 0) {
                    Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(bufferedInputStream);
                    keyStore.setCertificateEntry(certFile, certificate);
                }
            }
        }
        keyStore.store(new FileOutputStream(trustStorePath), trustStorePassword);
        return keyStore;
    }

    public HttpResponse<String> callEndpointAndGetStatusCode(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(url))
                .build();
        HttpResponse<String> response = HttpClient
                .newBuilder()
                .build()
                .send(request, HttpResponse.BodyHandlers.ofString());

        response.headers().map().forEach((k, v) -> System.out.println(k + "=" + v));

        int statusCode = response.statusCode();
        System.out.println(statusCode);
        System.out.println(response.body());
        return response;
    }
}
