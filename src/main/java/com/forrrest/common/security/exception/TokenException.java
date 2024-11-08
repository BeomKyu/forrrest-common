package com.forrrest.common.security.exception;

import lombok.Getter;

@Getter
public class TokenException extends RuntimeException {
    private final TokenExceptionType type;

    public TokenException(TokenExceptionType type) {
        super(type.getMessage());
        this.type = type;
    }

    public TokenException(TokenExceptionType type, Throwable cause) {
        super(type.getMessage(), cause);
        this.type = type;
    }
}
