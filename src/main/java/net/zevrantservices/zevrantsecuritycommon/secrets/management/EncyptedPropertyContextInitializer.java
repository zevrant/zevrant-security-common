package net.zevrantservices.zevrantsecuritycommon.secrets.management;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.*;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;

import java.security.InvalidParameterException;
import java.util.Base64;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;


public class EncyptedPropertyContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    private final Logger logger = LoggerFactory.getLogger(EncyptedPropertyContextInitializer.class);

    private PropertySource<Object> getSecret(String secretName, String region, String secretPrefix) {

        // Create a Secrets Manager client
        AWSSecretsManager client  = AWSSecretsManagerClientBuilder.standard()
                .withRegion(region)
                .build();

        // In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
        // See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        // We rethrow the exception by default.

        String plainTextString;
        GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
                .withSecretId(secretName);
        GetSecretValueResult getSecretValueResult;

        try {
            getSecretValueResult = client.getSecretValue(getSecretValueRequest);
        } catch (DecryptionFailureException | InvalidRequestException | ResourceNotFoundException | InvalidParameterException | InternalServiceErrorException e) {
            // Secrets Manager can't decrypt the protected secret text.
            // Deal with the exception here, and/or rethrow at your discretion.
            logger.error("Failed to decrypt requested secret, please ensure that the provided secret exists in the specified region");
            logger.error(e.getLocalizedMessage());
            throw e;
        }


        // Decrypts secret using the associated KMS CMK.
        // Depending on whether the secret is a string or binary, one of these fields will be populated.
        if (getSecretValueResult.getSecretString() != null) {
            plainTextString = getSecretValueResult.getSecretString();
        }
        else {
            plainTextString = new String(Base64.getDecoder().decode(getSecretValueResult.getSecretBinary()).array());
        }

        return new DecryptedPropertySource<Object>(secretPrefix.concat(secretName), plainTextString);
    }

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        ConfigurableEnvironment environment = applicationContext.getEnvironment();
        String secretPrefix = "encrypted.properties";
        Stream<String> encryptedProperties = Stream.of(StringUtils.defaultIfBlank(environment.getProperty(secretPrefix), "").split(","));
        encryptedProperties.forEach(property -> environment.getPropertySources().addLast(getSecret(property, Regions.US_EAST_1.getName(), secretPrefix.concat("."))));
    }
}
