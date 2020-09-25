package net.zevrant.services.security.common.secrets.management.rest.response;

import java.security.Principal;

public class ZevrantPrincipal implements Principal {

    private String username;

    public ZevrantPrincipal() {
    }

    public ZevrantPrincipal(String username) {
        this.username = username;
    }

    @Override
    public String getName() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
