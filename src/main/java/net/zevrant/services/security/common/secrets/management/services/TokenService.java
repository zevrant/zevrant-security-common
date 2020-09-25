package net.zevrant.services.security.common.secrets.management.services;

import net.zevrant.services.security.common.secrets.management.rest.response.AccessToken;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

public class TokenService {

    private RestTemplate restTemplate;
    private String username;
    private String password;
    private String oauthUrl;
    public TokenService(RestTemplate restTemplate, String oauthUrl, String username, String password) {
        this.restTemplate = restTemplate;
        this.username = username;
        this.password = password;
        this.oauthUrl = oauthUrl;
    }

    public String getToken() {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        body.set("client_id", this.username);
        body.set("client_secret", this.password);
        body.set("grant_type", "client_credentials");
        body.set("scope", "DEFAULT");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<AccessToken> response = restTemplate.exchange(this.oauthUrl + "/zevrant-oauth2-service/oauth/token", HttpMethod.POST, entity, AccessToken.class);
        assert(response.getBody() != null);
        return response.getBody().getAccessToken();
    }
}
