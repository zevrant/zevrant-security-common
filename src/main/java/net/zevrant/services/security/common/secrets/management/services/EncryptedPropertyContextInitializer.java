package net.zevrant.services.security.common.secrets.management.services;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSSessionCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClient;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.*;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.zevrant.services.security.common.secrets.management.rest.response.AwsSessionCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.client.RestTemplate;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public class EncryptedPropertyContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    private static final Logger logger = LoggerFactory.getLogger(EncryptedPropertyContextInitializer.class);
    private final List supportedProfiles = Arrays.asList("develop", "prod");
    private final AwsSessionCredentialsProvider credentialsProvider = new AwsSessionCredentialsProvider();

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        String[] properties = Objects.requireNonNull(applicationContext.getEnvironment().getProperty("zevrant.encrypted.properties")).split(",");
        String region = "us-east-1";
        String roleArn = System.getenv("ROLE_ARN");
        String[] activeProfiles = applicationContext.getEnvironment().getActiveProfiles();
        // Create a Secrets Manager client
        AWSSecretsManagerClientBuilder clientBuilder = AWSSecretsManagerClientBuilder.standard()
                .withRegion(region);

        if(Arrays.stream(activeProfiles).anyMatch(supportedProfiles::contains)) {
            BasicSessionCredentials credentials = credentialsProvider.assumeRole(region, roleArn);
            clientBuilder.withCredentials(new AWSStaticCredentialsProvider(credentials));

        }
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
