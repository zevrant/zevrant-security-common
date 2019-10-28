package net.zevrantservices.zevrantsecuritycommon.secrets.management;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.Mockito.*;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest
public class EncryptedKeystoreInitializerTest {

    private EncryptedKeystoreInitializer encryptedKeystoreInitializer;

    @Autowired
    private ConfigurableEnvironment environment;

    @Before
    public void setup() {
        encryptedKeystoreInitializer = new EncryptedKeystoreInitializer();
    }

    @Test
    public void initializeTrustStoreIOExceptionKeystore() throws KeyStoreException {
        MutablePropertySources properties = Mockito.mock(MutablePropertySources.class);
        ArgumentCaptor<DecryptedPropertySource> captor = ArgumentCaptor.forClass(DecryptedPropertySource.class);

        encryptedKeystoreInitializer.initializeKeystores(environment, "encrypted.properties");

        MutablePropertySources sources = environment.getPropertySources();
        assertThat(sources, is(notNullValue()));

        boolean[] foundPropertySource = {false, false};

        sources.stream().forEach(propertySource -> {
            foundPropertySource[0] = foundPropertySource[0] || propertySource.getName().equals("zevrant.security.keystore");
            foundPropertySource[0] = foundPropertySource[0] || propertySource.getName().contains("zevrant.security.trusted.certs");
        });

        assertThat(foundPropertySource[0], is(true));
    }
}
