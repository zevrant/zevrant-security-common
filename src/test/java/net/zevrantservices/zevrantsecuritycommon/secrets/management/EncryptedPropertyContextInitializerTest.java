package net.zevrantservices.zevrantsecuritycommon.secrets.management;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MutablePropertySources;

import java.security.KeyStore;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class EncryptedPropertyContextInitializerTest {

    private EncryptedPropertyContextInitializer initializer;

    @Mock
    private ConfigurableApplicationContext context;

    @Mock
    private ConfigurableEnvironment environment;

    @Mock
    private MutablePropertySources properties;

    @Captor
    private ArgumentCaptor<DecryptedPropertySource> propertyCaptor;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        initializer = new EncryptedPropertyContextInitializer();

        given(context.getEnvironment()).willReturn(environment);
        given(environment.getPropertySources()).willReturn(properties);
        given(environment.getProperty("keystores")).willReturn("dev/oauth/dev-oauth.p12");
        given(environment.getProperty("encrypted.properties.dev.oauthpassword")).willReturn("");
        given(environment.getProperty("trusted.cert")).willReturn("8eba18bc-885d-4775-af5b-294cc6105961");
    }

    @Test
    public void initialize() {
        given(environment.getProperty("encrypted.properties")).willReturn("dev/test");

        initializer.initialize(context);

        verify(properties, times(3)).addLast(propertyCaptor.capture());

        DecryptedPropertySource property = propertyCaptor.getAllValues().get(0);
        assertThat(property.getSource(), is("test"));
    }

    @Test
    public void initializeDecryptedUsernamePassword() {
        given(environment.getProperty("encrypted.properties")).willReturn("dev.oauth.keystore.credentials");

        initializer.initialize(context);

        verify(properties, times(3)).addLast(propertyCaptor.capture());

        DecryptedPropertySource property = propertyCaptor.getAllValues().get(0);
        assertThat(property.getSource().getClass(), is(equalTo(UsernamePasswordProperty.class)));
        assertThat(((UsernamePasswordProperty) property.getSource()).getPassword(), is(notNullValue()));
        assertThat(((UsernamePasswordProperty) property.getSource()).getUsername(), is(notNullValue()));
    }

    @Test
    public void initializePropertyDoesNotExists() {
        given(environment.getProperty("encrypted.properties")).willReturn("does_not_exist");

        initializer.initialize(context);

        verify(properties, times(2)).addLast(propertyCaptor.capture());

        assertThat(propertyCaptor.getValue().getSource().getClass(), is(equalTo(KeyStore.class)));
        assertThat(propertyCaptor.getValue().getSource().getClass(), is(equalTo(KeyStore.class)));
    }
}
