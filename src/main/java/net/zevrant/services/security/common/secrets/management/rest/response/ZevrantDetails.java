package net.zevrant.services.security.common.secrets.management.rest.response;

public class ZevrantDetails {

    private String remoteAddress;
    private String sessionId;
    private String tokenValue;
    private String tokenType;
    private String decodedDetails;

    public ZevrantDetails() {
    }

    public ZevrantDetails(String remoteAddress, String sessionId, String tokenValue, String tokenType, String decodedDetails) {
        this.remoteAddress = remoteAddress;
        this.sessionId = sessionId;
        this.tokenValue = tokenValue;
        this.tokenType = tokenType;
        this.decodedDetails = decodedDetails;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public void setRemoteAddress(String remoteAddress) {
        this.remoteAddress = remoteAddress;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public void setTokenValue(String tokenValue) {
        this.tokenValue = tokenValue;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getDecodedDetails() {
        return decodedDetails;
    }

    public void setDecodedDetails(String decodedDetails) {
        this.decodedDetails = decodedDetails;
    }
}
