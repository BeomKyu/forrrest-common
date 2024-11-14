package com.forrrest.common.security.filter;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.forrrest.common.security.token.TokenProvider;
import com.forrrest.common.security.token.TokenType;

@Component
public class ProfileTokenFilter extends AbstractTokenFilter {
    public ProfileTokenFilter(@Qualifier("jwtTokenProvider")TokenProvider tokenProvider,
        @Value("${security.token.profile-paths}") String[] pathPatterns) {
        super(tokenProvider, pathPatterns);
    }

    @Override
    protected TokenType getExpectedTokenType() {
        return TokenType.PROFILE_ACCESS;
    }
}