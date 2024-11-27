package com.forrrest.common.security.token;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forrrest.common.security.authentication.NonceTokenAuthentication;
import com.forrrest.common.security.authentication.ProfileTokenAuthentication;
import com.forrrest.common.security.authentication.UserTokenAuthentication;
import com.forrrest.common.security.exception.ExpiredTokenException;
import com.forrrest.common.security.exception.InvalidSignatureException;
import com.forrrest.common.security.exception.InvalidTokenException;
import com.forrrest.common.security.exception.TokenException;
import com.forrrest.common.security.exception.TokenExceptionType;
import com.forrrest.common.security.userdetails.CustomUserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.security.SignatureException;

@Component("nonceTokenProvider")
public class ExternalNonceTokenProvider implements TokenProvider{
    @Override
    public String createToken(String subject, TokenType tokenType) {
        return null;
    }

    @Override
    public String createToken(String subject, TokenType tokenType, Map<String, Object> claims) {
        return null;
    }

    @Override
    public boolean validateToken(String token) {
        try {
            /*
            web request forrest-appmanagementservice /nonce-tokens/validate
             */
            return true;
        } catch (ExpiredJwtException e) {
            throw new ExpiredTokenException();
        } catch (SignatureException e) {
            throw new InvalidSignatureException();
        } catch (MalformedJwtException e) {
            throw new InvalidTokenException();
        } catch (UnsupportedJwtException e) {
            throw new TokenException(TokenExceptionType.UNSUPPORTED_TOKEN);
        }
    }

    @Override
    public boolean validateTokenType(String token, TokenType expectedType) {
        Claims claims = getClaims(token);
        String tokenType = claims.get("tokenType", String.class);

        if (tokenType == null) {
            throw new TokenException(TokenExceptionType.WRONG_TYPE);
        }

        try {
            TokenType actualType = TokenType.valueOf(tokenType);
            return actualType == expectedType;
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenExceptionType.WRONG_TYPE);
        }
    }

    @Override
    public Claims getClaims(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                throw new InvalidTokenException();
            }
            // JWT의 페이로드 부분을 디코딩
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            // Jackson ObjectMapper를 사용하여 페이로드를 Map 객체로 변환
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> claimsMap = mapper.readValue(payload, new TypeReference<Map<String, Object>>() {
            });

            // Map을 Claims 객체로 변환
            return new DefaultClaims(claimsMap);
        } catch (Exception e) {
            throw new InvalidTokenException();
        }
    }

    @Override
    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);

        if (claims.get("roles") == null) {
            throw new TokenException(TokenExceptionType.EMPTY_CLAIMS);
        }

        CustomUserDetails userDetails = CustomUserDetails.builder()
            .id(claims.getSubject())
            .username(claims.get("username", String.class))
            .roles(claims.get("roles", List.class))
            .enabled(true)
            .clientId(claims.get("clientId", String.class))
            .build();

        String tokenType = claims.get("tokenType", String.class);
        if (tokenType == null) {
            throw new TokenException(TokenExceptionType.WRONG_TYPE);
        }

        try {
            TokenType type = TokenType.valueOf(tokenType);
            return switch (type) {
                case USER_ACCESS -> new UserTokenAuthentication(userDetails, token);
                case PROFILE_ACCESS -> new ProfileTokenAuthentication(userDetails, token);
                case NONCE -> new NonceTokenAuthentication(userDetails, token);
                default -> throw new TokenException(TokenExceptionType.WRONG_TYPE);
            };
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenExceptionType.WRONG_TYPE);
        }
    }
}
