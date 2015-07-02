/*
 * Tomitribe Confidential
 *
 * Copyright(c) Tomitribe Corporation. 2015
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */
package com.tomitribe.auth.signatures.cli;

import com.tomitribe.auth.signatures.cxf.feature.SecurityFeature;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.feature.LoggingFeature;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.transport.http.HTTPConduit;
import org.tomitribe.util.IO;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

/**
 * Description.
 *
 * @author Roberto Cortez
 */
public class SignatureVerifier {
    private SignatureVerifier() {
        throw new UnsupportedOperationException();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 5 || args.length > 6) {
            System.out.println("Usage: secret alias address path method [payload]");
            System.exit(-1);
        }

        final String secret = args[0];
        final String alias = args[1];
        final String address = args[2];
        final String path = args[3];

        System.out.println("secret = " + secret);
        System.out.println("alias = " + alias);
        System.out.println("address = " + address);
        System.out.println("path = " + path);

        WebClient webClient = WebClient
                .create(address, Collections.emptyList(),
                    Arrays.asList(new SecurityFeature(
                        "sha-256",
                        secret,
                        alias,
                        "hmac-sha256",
                        "(request-target) date digest"
                    ), new LoggingFeature()), null)
                .path(path);

        final HTTPConduit conduit = WebClient.getConfig(webClient).getHttpConduit();

        TLSClientParameters params = new TLSClientParameters();
        params.setTrustManagers(new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }});
        params.setDisableCNCheck(true);
        conduit.setTlsClientParameters(params);

        final Response response = webClient.invoke(args[4], args.length == 6 ? args[5] : null);
        System.out.println(response.getStatus());
        System.out.println(IO.slurp(InputStream.class.cast(response.getEntity())));
    }
}
