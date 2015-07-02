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
import org.tomitribe.crest.Main;
import org.tomitribe.crest.api.Command;
import org.tomitribe.crest.api.Default;
import org.tomitribe.crest.api.Exit;
import org.tomitribe.crest.api.Option;
import org.tomitribe.crest.api.Required;
import org.tomitribe.crest.cmds.CommandFailedException;
import org.tomitribe.crest.environments.SystemEnvironment;
import org.tomitribe.util.IO;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;

public final class SignatureVerifier {
    private SignatureVerifier() {
        // no-op
    }

    @Command
    public static void verify(
        @Option("alias") @Required final String alias,
        @Option("secret") @Required final String secret,
        @Option("endpoint") @Required final String endpoint,
        @Option("digest-algorithm") @Default("sha-256") final String digest,
        @Option("signature-algorithm") @Default("hmac-sha256") final String signature,
        @Option("headers") @Default("(request-target) date digest") final String headers,
        @Option("http-method") @Default("GET") final String method,
        @Option("payload") final String payload,
        @Option("type") final String type,
        @Option("accept") final String accept,
        @Option("request-headers") final String[] customHeaders // --request-headers=custom1=val1 --request-headers=custom2=val2
    ) throws Exception {
        final WebClient webClient = WebClient
            .create(endpoint, emptyList(),
                asList(new SecurityFeature(
                    digest,
                    secret,
                    alias,
                    signature,
                    headers
                ), new LoggingFeature()), null);
        if (type != null) {
            webClient.type(type);
        }
        if (accept != null) {
            webClient.accept(accept);
        }
        if (customHeaders != null) {
            for (final String h : customHeaders) {
                final int eq = h.indexOf('=');
                if (eq < 0) {
                    webClient.header(h, "");
                } else {
                    webClient.header(h.substring(0, eq), h.substring(eq + 1, h.length()));
                }
            }
        }

        if (endpoint.startsWith("https")) {
            final HTTPConduit conduit = WebClient.getConfig(webClient).getHttpConduit();

            final TLSClientParameters params = new TLSClientParameters();
            params.setTrustManagers(new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
                    // no-op
                }

                @Override
                public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
                    // no-op
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            }});
            params.setDisableCNCheck(true);
            conduit.setTlsClientParameters(params);
        }

        final Response response = webClient.invoke(method, payload);
        System.out.println(response.getStatus());
        System.out.println(IO.slurp(InputStream.class.cast(response.getEntity())));
    }

    public static void main(final String[] args) throws Exception {
        try {
            new Main(SignatureVerifier.class).main(new SystemEnvironment(), args);
        } catch (final CommandFailedException cfe) {
            final Throwable cause = cfe.getCause();
            final Exit exit = cause.getClass().getAnnotation(Exit.class);
            if (exit != null) {
                System.err.println(cfe.getMessage());
                System.exit(exit.value());
            } else {
                cause.printStackTrace();
                System.exit(-1);
            }
        } catch (final Exception var5) {
            System.exit(-1);
        }
    }
}
