package com.zevrant.services.zevrantsecuritycommon.config;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.StringUtils;

import java.util.*;

public class KeycloakGrantedAuthoritiesMapper implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String claimName = "realm_access";
    private static final Logger logger = LoggerFactory.getLogger(KeycloakGrantedAuthoritiesMapper.class);
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter;

    public KeycloakGrantedAuthoritiesMapper() {
        this.jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        Collection<GrantedAuthority> authorities = new HashSet<>();
        Map<String, Object> claims = source.getClaims();
        if (claims != null) {
            if (claims.containsKey("clientId")) {
                String clientId = (String) claims.get("clientId");
                authorities.addAll(getRealmAccessRoles((Map<String, Object>) claims.get("realm_access")));
                authorities.addAll(getResourceAccessRoles((Map<String, Object>) claims.get("resource_access"), clientId));
            } else if (claims.containsKey("preferred_username")
                    && claims.containsKey("azp")) {
                String clientId = (String) claims.get("preferred_username");
                authorities.addAll(getRealmAccessRoles((Map<String, Object>) claims.get("realm_access")));
            }
        }
        authorities.addAll(jwtGrantedAuthoritiesConverter.convert(source));
        return authorities;
    }

    private Collection<GrantedAuthority> getResourceAccessRoles(Map<String, Object> resourceAccess, String clientId) {
        if (resourceAccess != null && resourceAccess.containsKey(clientId)) {
            JSONArray roles = (JSONArray) ((JSONObject) ((JSONObject) resourceAccess
                    .get(clientId))
                    .get(clientId))
                    .get("roles");
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            roles.forEach(role -> authorities.add(new SimpleGrantedAuthority(role.toString())));
            return authorities;
        }
        return Collections.emptyList();
    }

    private Collection<GrantedAuthority> getRealmAccessRoles(Map<String, Object> realmAccess) {
        if (realmAccess != null && realmAccess.containsKey("roles")) {
            Collection<GrantedAuthority> authorities = new ArrayList<>();
            JSONArray rolesJson = (JSONArray) realmAccess.get("roles");
            rolesJson.forEach(role -> authorities.add(new SimpleGrantedAuthority(role.toString())));
            return authorities;
        }
        return Collections.emptyList();
    }

    private Collection<String> getAuthorities(Jwt jwt) {
        if (logger.isTraceEnabled()) {
            logger.trace("Looking for roles in claim {}", claimName);
        }
        Object authorities = jwt.getClaim(claimName);
        if (authorities instanceof String) {
            if (StringUtils.hasText((String) authorities)) {
                return Arrays.asList(((String) authorities).split(" "));
            }
            return Collections.emptyList();
        }
        if (authorities instanceof Collection) {
            return null;
        }
        return Collections.emptyList();
    }

    public void setAuthorityPrefix(String authorityPrefix) {
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix(authorityPrefix);
    }

    /**
     * Sets the name of token claim to use for mapping {@link GrantedAuthority
     * authorities} by this converter. Defaults to
     * {@link JwtGrantedAuthoritiesConverter#WELL_KNOWN_AUTHORITIES_CLAIM_NAMES}.
     *
     * @param authoritiesClaimName The token claim name to map authorities
     * @since 5.2
     */
    public void setAuthoritiesClaimName(String authoritiesClaimName) {
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(authoritiesClaimName);
    }

}
