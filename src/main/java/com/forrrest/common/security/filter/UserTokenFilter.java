package com.forrrest.common.security.filter;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.forrrest.common.security.token.TokenProvider;
import com.forrrest.common.security.token.TokenType;

@Component
public class UserTokenFilter extends AbstractTokenFilter {
    public UserTokenFilter(@Qualifier("jwtTokenProvider")TokenProvider tokenProvider,
        @Value("${security.token.user-paths}") String[] pathPatterns) {
        super(tokenProvider, pathPatterns);
    }

    @Override
    protected TokenType getExpectedTokenType() {
        return TokenType.USER_ACCESS;
    }
}