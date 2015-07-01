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

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.transport.http.HTTPConduit;
import org.tomitribe.auth.signatures.Base64;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;
import org.tomitribe.util.IO;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

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
        final String method = args[4];
        final String payload;
        if (args.length == 6) {
            payload = args[5];
        } else {
            payload = "";
        }

        System.out.println("secret = " + secret);
        System.out.println("alias = " + alias);
        System.out.println("address = " + address);
        System.out.println("path = " + path);
        System.out.println("method = " + method);
        System.out.println("input = " + payload);

        final String today = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US).format(new Date());
        final String digest =
                "SHA=" + new String(Base64.encodeBase64(MessageDigest.getInstance("SHA1").digest(payload.getBytes())));

        final SecretKey secretKey = new SecretKeySpec(secret.getBytes(), "hmacSHA256");
        final Signature signature = new Signature(alias, "hmac-sha256", null, "(request-target)", "digest", "date");
        final Map<String, String> headers = new HashMap<>();
        headers.put("Date", today);
        headers.put("Digest", digest);

        final Signature sign = new Signer(secretKey, signature).sign(method, path, headers);
        System.out.println(sign);

        WebClient webClient = WebClient
                .create(address)
                .path(path)
                .header("Authorization", sign)
                .header("Date", today)
                .header("Digest", digest);

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

        final Response response = webClient.get();
        System.out.println(response.getStatus());
        System.out.println(IO.slurp(InputStream.class.cast(response.getEntity())));
    }
}
