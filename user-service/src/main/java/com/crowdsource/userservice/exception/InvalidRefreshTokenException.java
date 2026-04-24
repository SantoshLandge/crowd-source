package com.crowdsource.userservice.exception;

public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException(String invalidRefreshToken) {
        super(invalidRefreshToken);
    }

}
