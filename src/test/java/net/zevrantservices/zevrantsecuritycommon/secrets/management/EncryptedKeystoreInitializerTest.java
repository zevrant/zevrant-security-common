package net.zevrantservices.zevrantsecuritycommon.secrets.management;

import com.amazonaws.services.s3.model.AmazonS3Exception;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MutablePropertySources;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Enumeration;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

public class EncryptedKeystoreInitializerTest {

    private EncryptedKeystoreInitializer encryptedKeystoreInitializer;

    @Mock
    private ConfigurableEnvironment environment;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
        encryptedKeystoreInitializer = new EncryptedKeystoreInitializer();
    }

    @Test
    public void initializeKeystore() throws KeyStoreException {
        ArgumentCaptor<DecryptedPropertySource> captor = ArgumentCaptor.forClass(DecryptedPropertySource.class);
        MutablePropertySources properties = Mockito.mock(MutablePropertySources.class);

        given(environment.getPropertySources()).willReturn(properties);
        given(environment.getProperty("keystores")).willReturn("dev/oauth/dev-oauth.p12");
        given(environment.getProperty("encrypted.properties.dev.oauthpassword")).willReturn("");
        given(environment.getProperty("trusted.certs")).willReturn("8eba18bc-885d-4775-af5b-294cc6105961");

        encryptedKeystoreInitializer.initializeKeystores(environment, "encrypted.properties");

        verify(properties, times(2)).addFirst(captor.capture());
        List<DecryptedPropertySource> decryptedPropertySources = captor.getAllValues();
        KeyStore keyStore = (KeyStore) decryptedPropertySources.get(0).getSource();
        KeyStore trustStore = (KeyStore) decryptedPropertySources.get(1).getSource();

        assertThat(keyStore, is(notNullValue()));
        assertThat(trustStore, is(notNullValue()));
        assertThat(keyStore.containsAlias("1"), is(true));
        assertThat(trustStore.aliases().hasMoreElements(), is(true));
    }

    @Test
    public void initializeKeystoreIOExceptionKeystore() {
        MutablePropertySources properties = Mockito.mock(MutablePropertySources.class);

        given(environment.getPropertySources()).willReturn(properties);
        given(environment.getProperty("keystores")).willReturn("DOES_NOT_EXIST");
        given(environment.getProperty("encrypted.properties.dev.oauthpassword")).willReturn("");
        given(environment.getProperty("trusted.certs")).willReturn("8eba18bc-885d-4775-af5b-294cc6105961");

        encryptedKeystoreInitializer.initializeKeystores(environment, "encrypted.properties");

        verify(properties, never()).addFirst(any());
    }

    @Test
    public void initializeTrustStoreIOExceptionKeystore() throws KeyStoreException {
        MutablePropertySources properties = Mockito.mock(MutablePropertySources.class);
        ArgumentCaptor<DecryptedPropertySource> captor = ArgumentCaptor.forClass(DecryptedPropertySource.class);

        given(environment.getPropertySources()).willReturn(properties);
        given(environment.getProperty("keystores")).willReturn("dev/oauth/dev-oauth.p12");
        given(environment.getProperty("encrypted.properties.dev.oauthpassword")).willReturn("");
        given(environment.getProperty("trusted.certs")).willReturn("does_not_exist");

        encryptedKeystoreInitializer.initializeKeystores(environment, "encrypted.properties");

        verify(properties).addFirst(captor.capture());

        KeyStore keyStore = (KeyStore) captor.getValue().getSource();

        assertThat(keyStore, is(notNullValue()));
        assertThat(keyStore.containsAlias("1"), is(true));
    }
}
