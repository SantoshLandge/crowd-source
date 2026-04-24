package com.crowdsource.userservice.exception;

public class DuplicateEntityException extends RuntimeException {
    public DuplicateEntityException(String emailAlreadyExists) {
        super(emailAlreadyExists);
    }
}
