package net.zevrantservices.zevrantsecuritycommon.secrets.management;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.certificatemanager.AWSCertificateManager;
import com.amazonaws.services.certificatemanager.AWSCertificateManagerClientBuilder;
import com.amazonaws.services.certificatemanager.model.GetCertificateRequest;
import com.amazonaws.services.certificatemanager.model.GetCertificateResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.AmazonS3Exception;
import com.amazonaws.services.s3.model.S3Object;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.stream.Stream;

public class EncryptedKeystoreInitializer {

    private static final Logger logger = LoggerFactory.getLogger(EncryptedKeystoreInitializer.class);

    private AWSCertificateManager acmClient;
    private AmazonS3 s3Client;
    private CharsetEncoder charsetEncoder;
    public EncryptedKeystoreInitializer() {
        acmClient = AWSCertificateManagerClientBuilder.standard().withRegion("us-east-1").build();
        s3Client = AmazonS3ClientBuilder.standard().withRegion("us-east-1").build();
        charsetEncoder = StandardCharsets.UTF_8.newEncoder();
    }

    public void initializeKeystores(ConfigurableEnvironment environment, String secretPrefix) {
        String propertyPrefix = "keystores";
        Stream<String> encryptedProperties = Stream.of(StringUtils.defaultIfBlank(environment.getProperty(propertyPrefix), "").split(","));
        encryptedProperties.forEach(property -> {
            try {

                String password = property.replaceAll("/", ".");
                password= password.substring(0, password.length() - 4);
                password = secretPrefix.concat(".".concat(password).concat(".password"));
                environment.getPropertySources().addFirst(getKeys(property, StringUtils.defaultIfBlank(environment.getProperty(password), "")));
                trustCertificates(environment);
            } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException  | AmazonS3Exception e ) {
                logger.error("failed to deserialize keystore");
                logger.error(e.getMessage());
            }
        });

    }

    private void trustCertificates(ConfigurableEnvironment environment) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        String propertyPrefix = "trusted.certs";
        Stream<String> encryptedProperties = Stream.of(StringUtils.defaultIfBlank(environment.getProperty(propertyPrefix), "").split(","));
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        encryptedProperties.forEach(property -> {
            try {
                trustCertificate(getCertificate(Regions.US_EAST_1.getName(), property), trustStore, property);
            } catch (CertificateException | KeyStoreException | com.amazonaws.services.certificatemanager.model.ResourceNotFoundException e) {
                logger.error("failed to trust certificate {} because {}", property, e.getMessage());
            }
        });
        if(trustStore.aliases().hasMoreElements()) {
            environment.getPropertySources().addFirst(new DecryptedPropertySource<KeyStore>("trustStore", trustStore));
        }
    }

    private void trustCertificate(GetCertificateResult certificate, KeyStore keystore, String property) throws CertificateException, KeyStoreException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate cert = certFactory.generateCertificate(new ByteArrayInputStream(certificate.getCertificate().getBytes(StandardCharsets.UTF_8)));
        keystore.setCertificateEntry(property, cert);
    }

    private PropertySource<KeyStore> getKeys(String certificateName, String password) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        S3Object object = s3Client.getObject("zevrant-resources", certificateName);

        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(object.getObjectContent(), password.toCharArray());
        return new DecryptedPropertySource<>(certificateName, keystore);
    }


    private GetCertificateResult getCertificate(String region, String certificateName) {
        GetCertificateRequest getCertificateRequest = new GetCertificateRequest();
        getCertificateRequest.setCertificateArn("arn:aws:acm:".concat(region).concat(":725235728275:certificate/").concat(certificateName));
        return acmClient.getCertificate(getCertificateRequest);
    }
}
