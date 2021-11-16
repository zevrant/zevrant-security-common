package com.zevrant.services.zevrantsecuritycommon.services;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public class AwsSessionCredentialsProvider {

    private static final Logger logger = LoggerFactory.getLogger(AwsSessionCredentialsProvider.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("E MMM dd HH:mm:ss z yyyy");
    private final Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("3.210.165.61", 3128));
    private final String encoded;
    //Wed Feb 03 17:16:13 GMT 2021


    public AwsSessionCredentialsProvider() {
        this.encoded = new String(Base64.encodeBase64(System.getenv("PROXY_CREDENTIALS").getBytes()));
    }

    public AwsSessionCredentialsProvider(String encoded) {
        this.encoded = encoded;
    }

    public BasicSessionCredentials assumeRole(String region, String roleARN) {
        logger.info("assuming role {}", roleARN);
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
        System.setProperty("expiration", sessionCredentials.getExpiration().toString());
        return awsCredentials;
    }

    @Async
    public void assumeRoleKeepAlive(String region, String roleARN) {
        while (true) {
//            assumeRole(region, roleARN);

            String dateString = System.getProperty("expiration");
            LocalDateTime date = LocalDateTime.parse(dateString, formatter);
            long epochSecond = date.toEpochSecond(ZoneOffset.UTC);

            try {
                Thread.sleep((epochSecond - 1) * 1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Retrieves session token from ec2 instance metadata endpoint, and on failure, does nothing
     *
     * @param clientBuilder
     */
    void setAwsCredentials(AwsClientBuilder clientBuilder) {
        URL url = null;
        try {
            url = new URL("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance");
            ObjectMapper mapper = new ObjectMapper();

            HttpURLConnection con = (HttpURLConnection) url.openConnection(proxy);
            con.setRequestProperty("Proxy-Authorization", "Basic " + encoded);
            con.setRequestMethod("GET");
            clientBuilder.withCredentials(parseResponse(con));
        } catch (IOException e) {
            logger.error("Failed to retrieve session credentials!");
            String token = getMetadataToken();
            try {
                url = new URL("http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance");
                HttpURLConnection con = (HttpURLConnection) url.openConnection(proxy);
                con.setRequestMethod("GET");
                con.setRequestProperty("X-aws-ec2-metadata-token", token);
                con.setRequestProperty("Proxy-Authorization", "Basic " + encoded);
                clientBuilder.withCredentials(parseResponse(con));
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private AWSStaticCredentialsProvider parseResponse(HttpURLConnection con) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));
        StringBuilder output = new StringBuilder();
        reader.lines().forEach(output::append);
        JSONObject jsonObject = new JSONObject(output.toString());

        BasicSessionCredentials basicSessionCredentials = new BasicSessionCredentials(
                jsonObject.getString("AccessKeyId"),
                jsonObject.getString("SecretAccessKey"),
                jsonObject.getString("Token"));

        return new AWSStaticCredentialsProvider(basicSessionCredentials);
    }

    private String getMetadataToken() {
        String token = "";
        try {
            URL url = new URL("http://169.254.169.254/latest/api/token");
            HttpURLConnection con = null;
            con = (HttpURLConnection) url.openConnection(proxy);
            con.setRequestMethod("POST");
            con.setRequestProperty("X-aws-ec2-metadata-token-ttl-seconds", "21600");
            con.setRequestProperty("Proxy-Authorization", "Basic " + encoded);
            BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()));
            StringBuilder output = new StringBuilder();
            reader.lines().forEach(output::append);
            token = output.toString();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        return token;
    }


}
