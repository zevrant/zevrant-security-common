package com.zevrant.services.zevrantsecuritycommon.services;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.response.AuthResponse;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class EncryptedPropertyContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    private static final List<String> profiles = Collections.unmodifiableList(List.of(
            "local",
            "develop",
            "prod"
    ));

    private static final Logger logger = LoggerFactory.getLogger(EncryptedPropertyContextInitializer.class);
    private final List<String> supportedProfiles;

    public EncryptedPropertyContextInitializer() {
        supportedProfiles = Arrays.asList("develop", "prod");
    }

    @Override
    public void initialize(ConfigurableApplicationContext applicationContext) {
        String[] properties = Objects.requireNonNull(applicationContext.getEnvironment().getProperty("zevrant.encrypted.properties")).split(",");
        String region = "us-east-1";
        String[] activeProfiles = applicationContext.getEnvironment().getActiveProfiles();

        List<String> profileList = Arrays.stream(activeProfiles)
                .filter(profiles::contains)
                .collect(Collectors.toList());
        if (profileList.size() > 1) {
            throw new RuntimeException("Only one profile of "
                    + profileList.stream().reduce((s, s2) -> s.concat(" ").concat(s2))
                    + " can be active at a time");
        }
        final String profile = profileList.get(0);
        final String vaultUrl = (profile.equals("prod"))
                ? "https://vault.zevrant-services.com"
                : "https://develop.vault.zevrant-services.com";

        try {
            VaultConfig vaultConfig = new VaultConfig()
                    .address(vaultUrl)
                    .build();
            Vault vault = new Vault(vaultConfig);
            String username = System.getenv("ACCESS_KEY_ID");
            String password = System.getenv("ACCESS_SECRET_KEY");
            AuthResponse authResponse = vault.auth().loginByUserPass(username, password, profile);
            String clientToken = authResponse.getAuthClientToken();
            vaultConfig = new VaultConfig()
                    .address(vaultUrl)
                    .token(clientToken)
                    .build();
            final Vault authenticatedVault = new Vault(vaultConfig);
            Arrays.stream(properties)
                    .forEach(property -> {
                        try {
                            final String secretPath = profile
                                    .concat("/")
                                    .concat(property);
                            logger.debug("Fetching {}", secretPath);
                            final String value = authenticatedVault
                                    .withRetries(5, 2000)
                                    .logical()
                                    .read(secretPath)
                                    .getData()
                                    .get("value");
                            if (StringUtils.isBlank(value)) {
                                throw new RuntimeException("Failed to retrieve secret " + property + ". secret not found.");
                            }
                            System.setProperty(property.replaceAll("/", "."), value);
                        } catch (VaultException e) {
                            logger.error(ExceptionUtils.getStackTrace(e));
                        }
                    });
        } catch (VaultException e) {
            logger.error(ExceptionUtils.getStackTrace(e));
        }


        // Create a Secrets Manager client
//        AWSSecretsManagerClientBuilder clientBuilder = AWSSecretsManagerClientBuilder.standard()
//                .withRegion(region);
//
//        AWSSecretsManager client = clientBuilder.build();
//
//        for(String profile : activeProfiles) {
//            for (String property : properties) {
//                GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
//                        .withSecretId("/" + profile + "/" + property);
//                GetSecretValueResult getSecretValueResult;
//
//                try {
//                    getSecretValueResult = client.getSecretValue(getSecretValueRequest);
//                    System.setProperty(property.replaceAll("/", "."), getSecretValueResult.getSecretString());
//                } catch (DecryptionFailureException | ResourceNotFoundException | InvalidRequestException
//                        | InvalidParameterException | InternalServiceErrorException e) {
//                    // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
//                    // Deal with the exception here, and/or rethrow at your discretion.
//                    logger.info("couldn't find property /{}/{}", profile, property);
//                }
//            }
//        }
    }
}
