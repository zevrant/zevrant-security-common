package net.zevrant.services.security.common.secrets.management.config;

import net.zevrant.services.security.common.secrets.management.filter.OAuthSecurityFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.web.client.RestTemplate;

public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    private final String baseUrl;
    private final RestTemplate restTemplate;
    private final AuthenticationManager authenticationManager;
    private final String[] unsecuredEndpoints;

    public WebSecurityConfigurer(@Value("${zevrant.services.proxy.baseUrl}") String baseUrl, RestTemplate restTemplate,
                                 AuthenticationManager authenticationManager,
                                 @Value("${zevrant.unsecured.endpoints:/actuator/health,/actuator/info,/actuator/prometheus}")
                                         String[] unsecuredEndpoints) {
        this.baseUrl = baseUrl;
        this.restTemplate = restTemplate;
        this.authenticationManager = authenticationManager;
        this.unsecuredEndpoints = unsecuredEndpoints;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .anonymous().and()
                .authorizeRequests().antMatchers(unsecuredEndpoints).permitAll()
                .and()
                .csrf().disable()
                .httpBasic().disable()
                .addFilterBefore(new OAuthSecurityFilter(this.baseUrl, this.restTemplate, this.authenticationManager), AnonymousAuthenticationFilter.class);
        super.configure(http);
    }

}
