package net.zevrant.services.security.common.secrets.management.rest.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.security.core.GrantedAuthority;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ZevrantGrantedAuthority implements GrantedAuthority {

    private String authority;

    public ZevrantGrantedAuthority() {
    }

    public ZevrantGrantedAuthority(String authority) {
        this.authority = authority;
    }

    @Override
    public String getAuthority() {
        return authority;
    }
}
