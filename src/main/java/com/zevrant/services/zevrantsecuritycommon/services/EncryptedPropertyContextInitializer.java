package com.zevrant.services.zevrantsecuritycommon.services;

import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class EncryptedPropertyContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    private static final Logger logger = LoggerFactory.getLogger(EncryptedPropertyContextInitializer.class);
    private final List<String> supportedProfiles;

    public EncryptedPropertyContextInitializer() {
        supportedProfiles = Arrays.asList("develop", "prod");
    }

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        String[] properties = Objects.requireNonNull(applicationContext.getEnvironment().getProperty("zevrant.encrypted.properties")).split(",");
        String region = "us-east-1";
        String roleArn = System.getenv("ROLE_ARN");
        String[] activeProfiles = applicationContext.getEnvironment().getActiveProfiles();
        // Create a Secrets Manager client
        AWSSecretsManagerClientBuilder clientBuilder = AWSSecretsManagerClientBuilder.standard()
                .withRegion(region);

        AWSSecretsManager client = clientBuilder.build();

        for(String profile : activeProfiles) {
            for (String property : properties) {
                GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
                        .withSecretId("/" + profile + "/" + property);
                GetSecretValueResult getSecretValueResult;

                try {
                    getSecretValueResult = client.getSecretValue(getSecretValueRequest);
                    System.setProperty(property.replaceAll("/", "."), getSecretValueResult.getSecretString());
                } catch (DecryptionFailureException | ResourceNotFoundException | InvalidRequestException
                        | InvalidParameterException | InternalServiceErrorException e) {
                    // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
                    // Deal with the exception here, and/or rethrow at your discretion.
                    logger.info("couldn't find property /{}/{}", profile, property);
                }
            }
        }
    }
}
