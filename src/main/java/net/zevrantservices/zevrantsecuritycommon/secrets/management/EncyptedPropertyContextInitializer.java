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
import org.springframework.core.env.PropertySource;

import java.security.InvalidParameterException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;


public class EncyptedPropertyContextInitializer implements ApplicationContextInitializer {

    private final Logger logger = LoggerFactory.getLogger(EncyptedPropertyContextInitializer.class);
    private final Pattern integerPattern;
    private final Pattern bytePattern;
    private final Pattern shortPattern;
    private final Pattern booleanPattern;
    private final Pattern longPattern;
    private final Pattern doublePattern;
    private final Pattern floatPattern;
    private final Pattern charPattern;


    public EncyptedPropertyContextInitializer() {
        integerPattern = Pattern.compile("\\d{1,10}");
        bytePattern = Pattern.compile("\\d{1, 3}");
        shortPattern = Pattern.compile("\\d{1,5}");
        booleanPattern = Pattern.compile("(true|false)");
        longPattern = Pattern.compile("\\d{0,19}");
        doublePattern = Pattern.compile("\\d{1," + 1.0E+307 +"}\\.\\d{1," + 1.0E+307 + "}");
        floatPattern = Pattern.compile("\\d{1," + 1.0E+44 +"}\\.\\d{1," + 1.0E+44 + "}");
        charPattern = Pattern.compile("\\w{1}");
    }


    private PropertySource getSecret(String secretName, String region) {

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

        return buildPropertySource(secretName, plainTextString);
    }

    private PropertySource buildPropertySource(String secretName, String plainTextString) {

    }

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        ConfigurableEnvironment environment = applicationContext.getEnvironment();
        Stream<String> encryptedProperties = Stream.of(StringUtils.defaultIfBlank(environment.getProperty("encrypted.properties"), "").split(","));
        encryptedProperties.forEach(property -> environment.getPropertySources().replace(property, getSecret(property, Regions.US_EAST_1.getName())));
    }
}
