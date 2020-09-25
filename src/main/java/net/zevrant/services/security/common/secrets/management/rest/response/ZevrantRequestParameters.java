package net.zevrant.services.security.common.secrets.management.rest.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ZevrantRequestParameters {

    private String client_id;

    public ZevrantRequestParameters() {
    }

    public ZevrantRequestParameters(String client_id) {
        this.client_id = client_id;
    }

    public String getClient_id() {
        return client_id;
    }

    public void setClient_id(String client_id) {
        this.client_id = client_id;
    }
}
