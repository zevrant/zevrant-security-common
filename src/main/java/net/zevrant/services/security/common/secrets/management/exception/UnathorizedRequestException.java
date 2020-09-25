package net.zevrant.services.security.common.secrets.management.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnathorizedRequestException extends RuntimeException {

    public UnathorizedRequestException(String message) {
        super(message);
    }
}
