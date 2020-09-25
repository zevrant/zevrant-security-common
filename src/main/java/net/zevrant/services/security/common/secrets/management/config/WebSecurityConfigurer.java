package net.zevrant.services.security.common.secrets.management.config;

import net.zevrant.services.security.common.secrets.management.filter.OAuthSecurityFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
        public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    private String baseUrl;
    private RestTemplate restTemplate;
    private AuthenticationManager authenticationManager;
    public WebSecurityConfigurer(@Value("${zevrant.services.proxy.baseUrl}") String baseUrl, RestTemplate restTemplate, AuthenticationManager authenticationManager) {
        this.baseUrl = baseUrl;
        this.restTemplate = restTemplate;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void configure(HttpSecurity security) throws Exception {
        security
                .authorizeRequests().antMatchers(new String[]{"/actuator/health", "/actuator/info", "/actuator"}).permitAll()
                .and()
                .csrf().disable()
                .httpBasic().disable()
                .addFilterBefore(new OAuthSecurityFilter(this.baseUrl, this.restTemplate, this.authenticationManager), AnonymousAuthenticationFilter.class);
//                .anonymous().disable();
    }

}
