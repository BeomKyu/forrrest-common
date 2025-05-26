package com.forrrest.common.security.exception;

import lombok.Getter;

@Getter
public class EmptySignatureException extends RuntimeException{
    private final TokenExceptionType type;

    public EmptySignatureException(TokenExceptionType type) {
        super(type.getMessage());
        this.type = type;
    }
}
