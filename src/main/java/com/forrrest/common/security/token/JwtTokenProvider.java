package com.forrrest.common.security.token;

import com.forrrest.common.security.authentication.NonceTokenAuthentication;
import com.forrrest.common.security.authentication.ProfileTokenAuthentication;
import com.forrrest.common.security.authentication.UserTokenAuthentication;
import com.forrrest.common.security.config.TokenProperties;
import com.forrrest.common.security.exception.*;
import com.forrrest.common.security.userdetails.CustomUserDetails;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Component("jwtTokenProvider")
@RequiredArgsConstructor
public class JwtTokenProvider implements TokenProvider {
    private final TokenProperties tokenProperties;

    private Key getSigningKey() {
        byte[] keyBytes = Base64.getDecoder().decode(tokenProperties.getSecret());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Override
    public String createToken(String subject, TokenType tokenType) {
        return createToken(subject, tokenType, Map.of());
    }

    @Override
    public String createToken(String subject, TokenType tokenType, Map<String, Object> claims) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + tokenProperties.getValidity().get(tokenType));

        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setIssuedAt(now)
            .setExpiration(validity)
            .claim("tokenType", tokenType.name())
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token);
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
            return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        } catch (JwtException e) {
            throw new InvalidTokenException();
        }
    }

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
            .build();

        String tokenType = claims.get("tokenType", String.class);
        if (tokenType == null) {
            throw new TokenException(TokenExceptionType.WRONG_TYPE);
        }

        try {
            TokenType type = TokenType.valueOf(tokenType);
            return switch (type) {
                case USER_ACCESS, USER_REFRESH -> new UserTokenAuthentication(userDetails, token);
                case PROFILE_ACCESS, PROFILE_REFRESH -> new ProfileTokenAuthentication(userDetails, token);
                case NONCE -> new NonceTokenAuthentication(userDetails, token);
                default -> throw new TokenException(TokenExceptionType.WRONG_TYPE);
            };
        } catch (IllegalArgumentException e) {
            throw new TokenException(TokenExceptionType.WRONG_TYPE);
        }
    }
}
