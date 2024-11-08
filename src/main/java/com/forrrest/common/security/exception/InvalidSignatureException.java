package com.forrrest.common.security.exception;

public class InvalidSignatureException extends TokenException {
    public InvalidSignatureException() {
        super(TokenExceptionType.INVALID_SIGNATURE);
    }
}