package com.crowdsource.userservice.exception;

public class ResourceNotFoundException extends RuntimeException {

    public ResourceNotFoundException(String invalidRefreshToken) {
        super(invalidRefreshToken);
    }

}
