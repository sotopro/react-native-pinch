package com.localz.pinch.utils;

import android.util.Base64;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class KeyPinStoreUtil {

    private final String TAG = "KeyPinStoreUtil";
    private static HashMap<String[], KeyPinStoreUtil> instances = new HashMap<>();
    private SSLContext sslContext = SSLContext.getInstance("TLS");

    public static synchronized KeyPinStoreUtil getInstance(String[] sslPinningCerts, String mutualAuthCert, String mutualAuthPassword) throws UnrecoverableKeyException,CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        if (instances.get(sslPinningCerts) == null) {
            instances.put(sslPinningCerts, new KeyPinStoreUtil(sslPinningCerts, mutualAuthCert, mutualAuthPassword));
        }
        return instances.get(sslPinningCerts);
    }

    private KeyPinStoreUtil(String[] sslPinningCerts, String mutualAuthCert, String mutualAuthPassword) throws UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        TrustManager[] trustManagers = null;
        KeyManager[] keyManagers = null;

        String keyStoreType = KeyStore.getDefaultType();

        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);

        if (!mutualAuthCert.isEmpty()) {
            KeyStore keyStoreMutual = KeyStore.getInstance("PKCS12");
            InputStream stream = new ByteArrayInputStream(Base64.decode(mutualAuthCert, Base64.DEFAULT));
            keyStoreMutual.load(stream, mutualAuthPassword.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStoreMutual, mutualAuthPassword.toCharArray());
            keyManagers = kmf.getKeyManagers();
        }

        if (sslPinningCerts != null && sslPinningCerts.length > 0) {

            for (String cert : sslPinningCerts) {
                    InputStream stream = new ByteArrayInputStream(Base64.decode(cert, Base64.DEFAULT));
                InputStream  caInput = new BufferedInputStream(stream);

                Certificate ca;
                try {
                    ca = cf.generateCertificate(caInput);
                    Log.d(TAG, "ca=" + ((X509Certificate) ca).getSubjectDN());
                } finally {
                    caInput.close();
                }

                keyStore.setCertificateEntry(cert, ca);
            }
            // Create a TrustManager that trusts the CAs in our KeyStore
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(keyStore);
            trustManagers = tmf.getTrustManagers();
        }


        sslContext.init(keyManagers, trustManagers, null);
    }

    public SSLContext getContext() {
        return sslContext;
    }
}
