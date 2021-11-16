package com.zevrant.services.zevrantsecuritycommon;

import org.springframework.core.env.PropertySource;

public class DecryptedPropertySource<T> extends PropertySource<T> {

    public DecryptedPropertySource(String name, T source) {
        super(name, source);
    }

    @Override
    public Object getProperty(String name) {
        return null;
    }

}
