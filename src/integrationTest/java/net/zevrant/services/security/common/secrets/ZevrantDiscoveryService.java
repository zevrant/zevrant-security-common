package com.zevrant.services.zevrantsecuritycommon.secrets;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.PropertySource;

@PropertySource("classpath:application-test.properties")
@SpringBootApplication
public class ZevrantDiscoveryService {

    public static void main(String[] args){
        SpringApplication.run(ZevrantDiscoveryService.class);
    }
}
