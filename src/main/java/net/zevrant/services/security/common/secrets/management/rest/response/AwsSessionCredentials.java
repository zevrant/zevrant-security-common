package net.zevrant.services.security.common.secrets.management.rest.response;

import org.codehaus.jackson.annotate.JsonProperty;

public class AwsSessionCredentials {

    @JsonProperty("Code")
    private String code;

    @JsonProperty("LastUpdated")
    private String lastUpdated;

    @JsonProperty("Type")
    private String type;

    @JsonProperty("AccessKeyId")
    private String accessKeyId;

    @JsonProperty("SecretAccessKey")
    private String secretAccessKey;

    @JsonProperty("Token")
    private String token;

    @JsonProperty("Expiration")
    private String expiration;

    public AwsSessionCredentials() {
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(String lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getAccessKeyId() {
        return accessKeyId;
    }

    public void setAccessKeyId(String accessKeyId) {
        this.accessKeyId = accessKeyId;
    }

    public String getSecretAccessKey() {
        return secretAccessKey;
    }

    public void setSecretAccessKey(String secretAccessKey) {
        this.secretAccessKey = secretAccessKey;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getExpiration() {
        return expiration;
    }

    public void setExpiration(String expiration) {
        this.expiration = expiration;
    }
}
