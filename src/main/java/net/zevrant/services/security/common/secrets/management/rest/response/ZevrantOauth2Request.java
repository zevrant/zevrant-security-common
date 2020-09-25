package net.zevrant.services.security.common.secrets.management.rest.response;

import java.util.List;

public class ZevrantOauth2Request {
    private String clientId;
    private List<String> scope;
    private ZevrantRequestParameters requestParameters;
    private List<String> resourceIds;
    private List<String> authorities;
    private boolean approved;
    private boolean refresh;
    private String redirectUri;
    private List<String> responseTypes;
    private ZevrantExtensions extensions;
    private String grantType;
    private String refreshTokenRequest;

    public ZevrantOauth2Request() {
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    public ZevrantRequestParameters getRequestParameters() {
        return requestParameters;
    }

    public void setRequestParameters(ZevrantRequestParameters requestParameters) {
        this.requestParameters = requestParameters;
    }

    public List<String> getResourceIds() {
        return resourceIds;
    }

    public void setResourceIds(List<String> resourceIds) {
        this.resourceIds = resourceIds;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public boolean isApproved() {
        return approved;
    }

    public void setApproved(boolean approved) {
        this.approved = approved;
    }

    public boolean isRefresh() {
        return refresh;
    }

    public void setRefresh(boolean refresh) {
        this.refresh = refresh;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public List<String> getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(List<String> responseTypes) {
        this.responseTypes = responseTypes;
    }

    public ZevrantExtensions getExtensions() {
        return extensions;
    }

    public void setExtensions(ZevrantExtensions extensions) {
        this.extensions = extensions;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getRefreshTokenRequest() {
        return refreshTokenRequest;
    }

    public void setRefreshTokenRequest(String refreshTokenRequest) {
        this.refreshTokenRequest = refreshTokenRequest;
    }
}
