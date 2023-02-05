package org.example;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

public class AppTestWithSSLContextSetDefault {
    private static SSLContext sslContextInitialState;
    private final String trustStoreType = "JKS";
    private final String trustStorePath = System.getProperty("java.io.tmpdir") + File.separator + "test.keystore";
    private final char[] trustStorePassword = "123456".toCharArray();
    private final String[] certs = {"root.crt"};

    @BeforeClass
    public static void saveSSLContextState() throws NoSuchAlgorithmException {
        sslContextInitialState = SSLContext.getDefault();
    }

    @Before
    public void setUp() {
        SSLContext.setDefault(sslContextInitialState);
        new File(trustStorePath).delete();
    }

    @Test(expected = Exception.class)
    public void should_fail_since_root_cert_is_not_part_of_java_cacerts() throws Exception {
        App app = new App();
        app.callEndpointAndGetStatusCode("https://untrusted-root.badssl.com/");
    }

    @Test
    public void should_pass_since_root_cert_was_added_manually_and_set_as_default_in_sslContext() throws Exception {
        App app = new App(trustStorePath, trustStorePassword, trustStoreType);
        app.setCustomTrustStoreInSSLContext(certs);
        app.callEndpointAndGetStatusCode("https://untrusted-root.badssl.com/");
    }

    @Test(expected = Exception.class)
    public void should_return_exception_since_we_are_using_custom_trustStore_which_is_missing_this_url_root_cert() throws Exception {
        App app = new App(trustStorePath, trustStorePassword, trustStoreType);
        app.setCustomTrustStoreInSSLContext(certs);
        app.callEndpointAndGetStatusCode("https://www.google.com/");
    }

    @Test
    public void should_return_200_since_we_are_using_certs_from_cacerts() throws Exception {
        assertEquals(200, new App().callEndpointAndGetStatusCode("https://www.google.com/").statusCode());
    }

    @Test
    public void should_return_200_since_we_are_using_custom_trustStore_with_all_cacerts_certificates() throws Exception {
        App app = new App(trustStorePath, trustStorePassword, trustStoreType);
        app.setCustomTrustStoreWithDefaultCertsInSSLContext(certs);
        assertEquals(200,app.callEndpointAndGetStatusCode("https://untrusted-root.badssl.com/").statusCode());
        assertEquals(200,app.callEndpointAndGetStatusCode("https://www.google.com/").statusCode());
    }
}
