package com.zevrant.services.zevrantsecuritycommon.config;

import com.zevrant.services.zevrantuniversalcommon.rest.generic.response.ApiError;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
@Component
public class ControllerAdvice {

    private static final Logger logger = LoggerFactory.getLogger(ControllerAdvice.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleException(Exception ex) {
        ApiError apiError = new ApiError();
        apiError.setExceptionClass(ex.getClass().toString());
        apiError.setErrorMessage(ex.getMessage());
        apiError.setResponseStatus(500);
        apiError.setStackTrace(ExceptionUtils.getStackTrace(ex));
        logger.error("ERROR: Internal server error {}", ex.getMessage());
        logger.error(ExceptionUtils.getStackTrace(ex));
        return new ResponseEntity<>(apiError, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiError> handleRuntimeException(RuntimeException ex) {
        Annotation[] annotations = ex.getClass().getAnnotations();
        List<Annotation> annotationList = Arrays.stream(annotations).filter(annotation -> annotation.annotationType().equals(ResponseStatus.class))
                .collect(Collectors.toList());
        int responseStatus = 500;
        if (annotationList.size() == 1) {
            ResponseStatus responseStatus1 = ex.getClass().getAnnotation(ResponseStatus.class);
            responseStatus = responseStatus1.code().value();
        } else {
            logger.info("Processed exception did not contain a @ResponseStatus annotation");
            logger.error("ERROR: Internal server error {}", ex.getMessage());
            logger.error(ExceptionUtils.getStackTrace(ex));
        }

        ApiError apiError = new ApiError();
        apiError.setExceptionClass(ex.getClass().toString());
        apiError.setErrorMessage(ex.getMessage());
        apiError.setResponseStatus(responseStatus);
        apiError.setStackTrace(ExceptionUtils.getStackTrace(ex));
        return new ResponseEntity<>(apiError, HttpStatus.valueOf(responseStatus));
    }
}
