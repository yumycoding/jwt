package com.yumyapps.jwt.exception.exceptions;

public class UsernameExistException extends RuntimeException {
    public UsernameExistException(String message) {
        super(message);
    }
}
