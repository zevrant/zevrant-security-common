package net.zevrant.services.security.common.secrets.management.services;

import org.junit.jupiter.api.Test;

class AwsSessionCredentialsProviderTest {

    private final AwsSessionCredentialsProvider credentialsProvider = new AwsSessionCredentialsProvider();


    @Test
    public void assumeRoleKeepAlive() {
        System.setProperty("expiration", "Wed Feb 03 17:16:13 GMT 2021");

        credentialsProvider.assumeRoleKeepAlive("us-east-1", "arn:aws:iam::725235728275:instance-profile/CameraClientServiceRole");
    }
}