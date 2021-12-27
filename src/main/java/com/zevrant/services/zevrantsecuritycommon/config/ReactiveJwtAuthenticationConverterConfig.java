package com.zevrant.services.zevrantsecuritycommon.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;

@Configuration
public class ReactiveJwtAuthenticationConverterConfig {

    @Bean
    public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {

        KeycloakGrantedAuthoritiesMapper mapper = new KeycloakGrantedAuthoritiesMapper();
        mapper.setAuthorityPrefix("");
        mapper.setAuthoritiesClaimName("realm_access");

        ReactiveJwtAuthenticationConverter jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                new ReactiveJwtGrantedAuthoritiesConverterAdapter(mapper));

        return jwtAuthenticationConverter;
    }
}
