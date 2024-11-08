package com.forrrest.common.security.token;

import io.jsonwebtoken.Claims;

import org.springframework.security.core.Authentication;

import java.util.Map;

public interface TokenProvider {
    String createToken(String subject, TokenType tokenType);
    String createToken(String subject, TokenType tokenType, Map<String, Object> claims);
    boolean validateToken(String token);
    boolean validateTokenType(String token, TokenType expectedType);
    Claims getClaims(String token);
    Authentication getAuthentication(String token);
}