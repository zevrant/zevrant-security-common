package net.zevrantservices.zevrantsecuritycommon.secrets.management;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.certificatemanager.AWSCertificateManager;
import com.amazonaws.services.certificatemanager.AWSCertificateManagerClientBuilder;
import com.amazonaws.services.certificatemanager.model.ExportCertificateRequest;
import com.amazonaws.services.certificatemanager.model.ExportCertificateResult;
import com.amazonaws.services.certificatemanager.model.GetCertificateRequest;
import com.amazonaws.services.certificatemanager.model.GetCertificateResult;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.jce.provider.PEMUtil;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;
import sun.security.validator.TrustStoreUtil;
import sun.security.x509.X509CertImpl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

public class EncryptedKeystoreInitializer {

    private static final Logger logger = LoggerFactory.getLogger(EncryptedKeystoreInitializer.class);

    private AWSCertificateManager client;
    private CharsetEncoder charsetEncoder;
    public EncryptedKeystoreInitializer() {
        client = AWSCertificateManagerClientBuilder.standard().withRegion("us-east-1").build();
        charsetEncoder = StandardCharsets.UTF_8.newEncoder();
    }

    public void initializeKeystores(ConfigurableEnvironment environment, String secretPrefix) {
        String propertyPrefix = "keystores";
        Stream<String> encryptedProperties = Stream.of(StringUtils.defaultIfBlank(environment.getProperty(propertyPrefix), "").split(","));
        encryptedProperties.forEach(property -> {
            try {
                environment.getPropertySources().addLast(getKeys(property, Regions.US_EAST_1.getName(), environment.getProperty(secretPrefix.concat(property))));
                trustCertificates(environment);
            } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
                logger.error("failed to deserialize keystore");
            }
        });

    }

    private void trustCertificates(ConfigurableEnvironment environment) {
        String propertyPrefix = "trusted.cert";
        Stream<String> encryptedProperties = Stream.of(StringUtils.defaultIfBlank(environment.getProperty(propertyPrefix), "").split(","));
        encryptedProperties.forEach(property -> {
            trustCertificate(getCertificate(Regions.US_EAST_1.getName(), property));
        });
    }

    private void trustCertificate(GetCertificateResult certificate, KeyStore ) {

    }

    private PropertySource<KeyStore> getKeys(String certificateName, String region, String password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        ExportCertificateRequest exportCertificateRequest = new ExportCertificateRequest();
        exportCertificateRequest.setCertificateArn("arn:aws:acm:".concat(region).concat("725235728275:certificate/").concat(certificateName));
        exportCertificateRequest.setPassphrase(charsetEncoder.encode(CharBuffer.wrap(password)));
        ExportCertificateResult result = client.exportCertificate(exportCertificateRequest);
        String certificate = result.getCertificate();
        String privateKey = result.getPrivateKey();
        return createKeystore(certificateName, certificate, privateKey);
    }

    private PropertySource<KeyStore> createKeystore(String certificateName, String publicKey, String privateKey) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null, null);
        X509Certificate[] certChain = new X509Certificate[1];
        certChain[0] = new X509CertImpl(publicKey.getBytes());
        keystore.setKeyEntry("me", privateKey.getBytes(), certChain);
        return new DecryptedPropertySource<>(certificateName, keystore);
    }

    private GetCertificateResult getCertificate(String region, String certificateName) {
        GetCertificateRequest getCertificateRequest = new GetCertificateRequest();
        getCertificateRequest.setCertificateArn("arn:aws:acm:".concat(region).concat("725235728275:certificate/").concat(certificateName));
        return client.getCertificate(getCertificateRequest);
    }
}
