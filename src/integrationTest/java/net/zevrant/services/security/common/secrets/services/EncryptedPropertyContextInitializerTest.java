package net.zevrant.services.security.common.secrets.services;

import net.zevrant.services.security.common.secrets.management.services.EncryptedPropertyContextInitializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.PropertySource;

@PropertySource("classpath:application-test.properties")
@SpringBootTest
public class EncryptedPropertyContextInitializerTest {

    @Autowired
    private ConfigurableApplicationContext applicationContext;

    private EncryptedPropertyContextInitializer initializer;

    @BeforeEach
    public void setup(){
        initializer = new EncryptedPropertyContextInitializer();
    }

    @Test
    public void initializeContext() {
        initializer.initialize(applicationContext);
    }

}
