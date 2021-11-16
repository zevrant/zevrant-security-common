package com.zevrant.services.zevrantsecuritycommon.config;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

public class RestTemplateConfig {

  @Bean
  public RestTemplate configure() {
    return new RestTemplateBuilder().build();
  }

}
