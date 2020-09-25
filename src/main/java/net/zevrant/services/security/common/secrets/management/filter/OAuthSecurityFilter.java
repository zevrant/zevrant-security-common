package net.zevrant.services.security.common.secrets.management.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.zevrant.services.security.common.secrets.management.exception.UnathorizedRequestException;
import net.zevrant.services.security.common.secrets.management.rest.response.ZevrantAuthentication;
import org.apache.http.entity.ContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class OAuthSecurityFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(OAuthSecurityFilter.class);

    private String proxyBaseUrl;
    private ObjectMapper objectMapper;
    private RestTemplate restTemplate;
    private AuthenticationManager authenticationManager;
    public OAuthSecurityFilter(String proxyBaseUrl, RestTemplate restTemplate, AuthenticationManager authenticationManager) {
        this.proxyBaseUrl = proxyBaseUrl;
        this.objectMapper = new ObjectMapper();
        this.restTemplate = restTemplate;
        this.authenticationManager = authenticationManager;
    }
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if(((HttpServletRequest) request).getRequestURI().contains("/actuator") ||
                ((HttpServletRequest) request).getRequestURI().contains("/error")){
            HttpServletResponse resp = ((HttpServletResponse) response);
            resp.reset();
            resp.setStatus(HttpStatus.ACCEPTED.value());
            resp.setContentType(ContentType.APPLICATION_JSON.toString());
        } else {
            String header = ((HttpServletRequest) request).getHeader("authorization");
            HttpHeaders headers = new HttpHeaders();
            headers.set("authorization", header);
            try {
                HttpEntity<String> entity = new HttpEntity<>("body", headers);
                ResponseEntity<ZevrantAuthentication> res = restTemplate.exchange(proxyBaseUrl + "/zevrant-oauth2-service/token", HttpMethod.GET, entity, ZevrantAuthentication.class);

                if (res.getStatusCode() == HttpStatus.OK && (res.getBody() != null
                        && !"anonymousUser".equals(res.getBody().getPrincipal()))) {
                    ZevrantAuthentication authentication = res.getBody();
                    SecurityContextHolder.getContext().setAuthentication(authenticationManager.authenticate(authentication));
                }
            } catch (HttpClientErrorException exception) {
                Authentication authentication = new ZevrantAuthentication();
                authentication.setAuthenticated(false);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                HttpServletResponse resp = ((HttpServletResponse) response);
                resp.reset();
                resp.setStatus(HttpStatus.UNAUTHORIZED.value());
                resp.setContentType(ContentType.APPLICATION_JSON.toString());
                resp.getOutputStream().write(objectMapper.writeValueAsBytes(new UnathorizedRequestException("Unauthorized")));
                logger.debug(exception.getMessage());
                logger.debug(exception.getStatusText());
                logger.debug(exception.getResponseBodyAsString());
                return;
            }
        }
        chain.doFilter(request, response);
    }
}