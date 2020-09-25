package net.zevrant.services.security.common.secrets.management.services;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.Objects;

public class EncryptedPropertyContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    private static final Logger logger = LoggerFactory.getLogger(EncryptedPropertyContextInitializer.class);

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        String[] properties = Objects.requireNonNull(applicationContext.getEnvironment().getProperty("zevrant.encrypted.properties")).split(",");
        String region = "us-east-1";
        String[] activeProfiles = applicationContext.getEnvironment().getActiveProfiles();
        // Create a Secrets Manager client
        AWSSecretsManager client  = AWSSecretsManagerClientBuilder.standard()
                .withRegion(region)
                .build();

        // In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
        // See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        // We rethrow the exception by default.


        for(String profile : activeProfiles) {
            for (String property : properties) {
                GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
                        .withSecretId("/" + profile + "/" + property);
                GetSecretValueResult getSecretValueResult;

                try {
                    getSecretValueResult = client.getSecretValue(getSecretValueRequest);
                    System.setProperty(property.replaceAll("/", "."), getSecretValueResult.getSecretString());
                } catch (DecryptionFailureException | ResourceNotFoundException | InvalidRequestException | InvalidParameterException | InternalServiceErrorException e) {
                    // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                    // Deal with the exception here, and/or rethrow at your discretion.
                    logger.info("couldn't find property /{}/{}", profile, property);
                }
            }
        }
    }
}
