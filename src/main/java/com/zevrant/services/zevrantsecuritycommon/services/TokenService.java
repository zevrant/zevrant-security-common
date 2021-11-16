package com.zevrant.services.zevrantsecuritycommon.services;

import com.zevrant.services.zevrantsecuritycommon.rest.response.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class TokenService {

    private final RestTemplate restTemplate;
    private final String clientId;
    private final String clientSecret;
    private final String oauthUrl;

    @Autowired
    public TokenService(RestTemplate restTemplate,
                        @Value("${zevrant.services.oauth.clientId}") String clientId,
                        @Value("${zevrant.services.oauth.clientSecret}") String clientSecret,
                        @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}") String oauthUrl) {
        this.restTemplate = restTemplate;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.oauthUrl = oauthUrl;
    }

    public AccessToken getToken() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.set("client_id", this.clientId);
        body.set("client_secret", this.clientSecret);
        body.set("grant_type", "client_credentials");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        ResponseEntity<AccessToken> response = restTemplate.exchange(this.oauthUrl + "/protocol/openid-connect/token",
                HttpMethod.POST, entity, AccessToken.class);
        assert (response.getBody() != null);
        return response.getBody();
    }
}
