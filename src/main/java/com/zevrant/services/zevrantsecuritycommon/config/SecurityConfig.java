package com.zevrant.services.zevrantsecuritycommon.config;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.server.SecurityWebFilterChain;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    @Bean
    public ReactiveClientRegistrationRepository clientRegistrations(@Value("${zevrant.services.oauth.clientId}") String clientId,
                                                                    @Value("${zevrant.services.oauth.clientSecret}") String clientSecret,
                                                                    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}") String oauthUrl) {
        ClientRegistration clientRegistration = ClientRegistrations
                .fromOidcIssuerLocation(oauthUrl)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .issuerUri(oauthUrl)
                .build();
        return new InMemoryReactiveClientRegistrationRepository(clientRegistration);
    }

    @Bean
    @Primary
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity,
                                                         @Value("${zevrant.unsecured.endpoints:/actuator/health,/actuator/info,/actuator/prometheus}") String[] unsecuredEndpoints) {

        return httpSecurity
                .httpBasic().disable()
                .formLogin().disable()
                .csrf().disable()
                .authorizeExchange()
                .pathMatchers(unsecuredEndpoints).permitAll()
                .anyExchange().authenticated()
                .and().oauth2Login()
                .and().oauth2ResourceServer().jwt(Customizer.withDefaults())
                .and().build();
    }
}