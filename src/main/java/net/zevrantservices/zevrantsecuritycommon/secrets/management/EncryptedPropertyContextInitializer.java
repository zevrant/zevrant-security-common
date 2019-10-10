package net.zevrantservices.zevrantsecuritycommon.secrets.management;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.Base64;
import java.util.stream.Stream;


public class EncryptedPropertyContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    private final Logger logger = LoggerFactory.getLogger(EncryptedPropertyContextInitializer.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    private PropertySource<? extends Object> getSecret(String secretName, String region, String secretPrefix) throws IOException{

        // Create a Secrets Manager client
        AWSSecretsManager client  = AWSSecretsManagerClientBuilder.standard()
                .withRegion(region)
                .build();

        // In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
        // See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        // We rethrow the exception by default.

        String plainTextString;
        GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest().withSecretId(secretName);
        GetSecretValueResult getSecretValueResult;

        try {
            getSecretValueResult = client.getSecretValue(getSecretValueRequest);
            if (getSecretValueResult.getSecretString() != null) {
                plainTextString = getSecretValueResult.getSecretString();
            }
            else {
                plainTextString = new String(Base64.getDecoder().decode(getSecretValueResult.getSecretBinary()).array());
            }

            return createDecryptedProperty(secretPrefix.concat(secretName), plainTextString);
        } catch (DecryptionFailureException | InvalidRequestException | ResourceNotFoundException | InvalidParameterException | InternalServiceErrorException | IOException e) {
            // Secrets Manager can't decrypt the protected secret text.
            // Deal with the exception here, and/or rethrow at your discretion.
            logger.error("Failed to decrypt requested secret, please ensure that the provided secret exists in the specified region");
            logger.error(e.getLocalizedMessage());
            throw e;
        }


        // Decrypts secret using the associated KMS CMK.
        // Depending on whether the secret is a string or binary, one of these fields will be populated.

    }

    private PropertySource<? extends Object> createDecryptedProperty(String secretName, String plainTextString) throws IOException{
        if(plainTextString.contains("username") && plainTextString.contains("password")) {
            UsernamePasswordProperty secretProperty = objectMapper.readValue(plainTextString, UsernamePasswordProperty.class);
            return new DecryptedPropertySource<>(secretName, secretProperty);
        }

        return new DecryptedPropertySource<>(secretName, plainTextString);
    }

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        ConfigurableEnvironment environment = applicationContext.getEnvironment();
        String secretPrefix = "encrypted.properties";
        String[] properties = StringUtils.defaultIfBlank(environment.getProperty(secretPrefix), "").split(",");
        Stream<String> encryptedProperties = Stream.of(properties);
        encryptedProperties.forEach(property -> {
            try {
                environment.getPropertySources().addLast(getSecret(property, Regions.US_EAST_1.getName(), secretPrefix.concat(".")));
            } catch (IOException | com.amazonaws.services.secretsmanager.model.ResourceNotFoundException e) {
                logger.error("failed to deserialize property");
            }
        });
        new EncryptedKeystoreInitializer().initializeKeystores(environment, secretPrefix);
    }
}
