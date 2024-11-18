package com.forrrest.common.security.filter;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.forrrest.common.security.token.TokenProvider;
import com.forrrest.common.security.token.TokenType;

@Component
public class ExternalNonceTokenFilter extends AbstractTokenFilter {

    public ExternalNonceTokenFilter(@Qualifier("nonceTokenProvider") TokenProvider tokenProvider,
        @Value("${security.token.external-nonce-paths}") String[] pathPatterns) {
        super(tokenProvider, pathPatterns);
    }

    protected TokenType getExpectedTokenType() {
        return TokenType.NONCE;
    }
}
