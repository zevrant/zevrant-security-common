package com.zevrant.services.zevrantsecuritycommon.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class HttpClientConfig {

  @Bean
  public RestTemplate configureRestTemplate() {
    return new RestTemplateBuilder().build();
  }

  @Bean
  public WebClient configureWebClient() {
    return WebClient.create();
  }

}
