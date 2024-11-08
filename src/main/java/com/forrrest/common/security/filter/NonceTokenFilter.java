package com.forrrest.common.security.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.forrrest.common.security.token.TokenProvider;
import com.forrrest.common.security.token.TokenType;

@Component
public class NonceTokenFilter extends AbstractTokenFilter {
    public NonceTokenFilter(TokenProvider tokenProvider,
        @Value("${security.token.nonce-paths}") String[] pathPatterns) {
        super(tokenProvider, pathPatterns);
    }

    @Override
    protected TokenType getExpectedTokenType() {
        return TokenType.NONCE;
    }
}