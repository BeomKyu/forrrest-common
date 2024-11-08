package com.forrrest.common.security.exception;

public class ExpiredTokenException extends TokenException {
    public ExpiredTokenException() {
        super(TokenExceptionType.EXPIRED);
    }
}