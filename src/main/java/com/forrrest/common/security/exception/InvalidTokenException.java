package com.forrrest.common.security.exception;

public class InvalidTokenException extends TokenException {
    public InvalidTokenException() {
        super(TokenExceptionType.INVALID_TOKEN);
    }
}