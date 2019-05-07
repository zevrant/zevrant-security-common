package net.zevrantservices.zevrantsecuritycommon.secrets.management;

import org.springframework.core.env.PropertySource;

public class DecryptedPropertySource<T> extends PropertySource<T> {

    public DecryptedPropertySource(String name, T source) {
        super(name, source);
    }

    public DecryptedPropertySource(String name) {
        super(name);
    }

    @Override
    public Object getProperty(String name) {
        return null;
    }
}
