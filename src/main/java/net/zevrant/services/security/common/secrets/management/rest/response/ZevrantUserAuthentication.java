package net.zevrant.services.security.common.secrets.management.rest.response;

import java.util.List;

public class ZevrantUserAuthentication {
    private List<String> authorities;
    private String details;
    private boolean authenticated;
    private String principal;
    private String credentials;
    private String name;

    public ZevrantUserAuthentication() {
    }

    public ZevrantUserAuthentication(List<String> authorities, String details, boolean authenticated, String principal, String credentials, String name) {
        this.authorities = authorities;
        this.details = details;
        this.authenticated = authenticated;
        this.principal = principal;
        this.credentials = credentials;
        this.name = name;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
