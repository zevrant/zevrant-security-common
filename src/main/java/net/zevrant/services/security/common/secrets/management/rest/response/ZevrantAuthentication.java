package net.zevrant.services.security.common.secrets.management.rest.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.Principal;
import java.util.Collection;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ZevrantAuthentication implements Authentication {

    private List<ZevrantGrantedAuthority> authorities;
    private Object credentials;
    private ZevrantDetails details;
    private ZevrantPrincipal principal;
    private boolean authenticated;
    private ZevrantUserAuthentication userAuthentication;
    private ZevrantOauth2Request oauth2Request;
    private boolean clientOnly;

    public ZevrantAuthentication() {
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        //no op
    }

    @Override
    public String getName() {
        return principal.getName();
    }

    public void setAuthorities(List<ZevrantGrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    public void setCredentials(Object credentials) {
        this.credentials = credentials;
    }

    public void setDetails(ZevrantDetails details) {
        this.details = details;
    }

    public void setPrincipal(ZevrantPrincipal principal) {
        this.principal = principal;
    }

    public ZevrantUserAuthentication getUserAuthentication() {
        return userAuthentication;
    }

    public void setUserAuthentication(ZevrantUserAuthentication userAuthentication) {
        this.userAuthentication = userAuthentication;
    }

    public ZevrantOauth2Request getOauth2Request() {
        return oauth2Request;
    }

    public void setOauth2Request(ZevrantOauth2Request oauth2Request) {
        this.oauth2Request = oauth2Request;
    }

    public boolean isClientOnly() {
        return clientOnly;
    }

    public void setClientOnly(boolean clientOnly) {
        this.clientOnly = clientOnly;
    }

}
