package net.zevrant.services.security.common.secrets.management.services;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.zevrant.services.security.common.secrets.management.rest.response.AwsSessionCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.UUID;

public class AwsSessionCredentialsProvider {

    private static final Logger logger = LoggerFactory.getLogger(AwsSessionCredentialsProvider.class);

    public BasicSessionCredentials assumeRole(String region, String roleARN) {
        AWSSecurityTokenServiceClientBuilder stsClientBuilder = AWSSecurityTokenServiceClientBuilder.standard();
        setAwsCredentials(stsClientBuilder);
        stsClientBuilder.setRegion(region);
        AWSSecurityTokenService stsClient = stsClientBuilder.build();

        AssumeRoleRequest roleRequest = new AssumeRoleRequest()
                .withRoleArn(roleARN)
                .withRoleSessionName(UUID.randomUUID().toString());
        AssumeRoleResult roleResponse = stsClient.assumeRole(roleRequest);
        Credentials sessionCredentials = roleResponse.getCredentials();

        // Create a BasicSessionCredentials object that contains the credentials you just retrieved.
        BasicSessionCredentials awsCredentials = new BasicSessionCredentials(
                sessionCredentials.getAccessKeyId(),
                sessionCredentials.getSecretAccessKey(),
                sessionCredentials.getSessionToken());

        System.setProperty("accessKeyId", sessionCredentials.getAccessKeyId());
        System.setProperty("secretAccessKey", sessionCredentials.getSecretAccessKey());
        System.setProperty("sessionToken", sessionCredentials.getSessionToken());

        return awsCredentials;
    }

    /**
     * Retrieves session token from ec2 instance metadata endpoint, and on failure, does nothing
     * @param clientBuilder
     */
    void setAwsCredentials(AwsClientBuilder clientBuilder) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            URL url = new URL("http://example.com");
            HttpURLConnection con = null;
            con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("GET");
            BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));
            StringBuilder output = new StringBuilder();
            reader.lines().forEach(output::append);
            AwsSessionCredentials credentials = mapper.readValue(output.toString(), AwsSessionCredentials.class);
            BasicSessionCredentials basicSessionCredentials = new BasicSessionCredentials(
                    credentials.getAccessKeyId(),
                    credentials.getSecretAccessKey(),
                    credentials.getToken());

            clientBuilder.withCredentials(new AWSStaticCredentialsProvider(basicSessionCredentials));
        } catch (IOException e) {
            logger.error("Failed to retrieve session credentials!");
            e.printStackTrace();
        }
    }


}
