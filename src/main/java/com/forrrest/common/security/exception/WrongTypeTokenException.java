package com.forrrest.common.security.exception;

public class WrongTypeTokenException extends TokenException {
    public WrongTypeTokenException() {
        super(TokenExceptionType.WRONG_TYPE);
    }
}