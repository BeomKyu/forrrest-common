package com.forrrest.common.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

import com.forrrest.common.security.config.JwtProperties;
import com.forrrest.common.security.userdetails.CustomUserDetails;

@Slf4j
@Getter
@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final JwtProperties jwtProperties;
    private Key key;

    @PostConstruct
    protected void init() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecret());
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(String email) {
        return createToken(email, jwtProperties.getAccessTokenValidityInMilliseconds());
    }

    public String createRefreshToken(String email) {
        return createToken(email, jwtProperties.getRefreshTokenValidityInMilliseconds());
    }

    private String createToken(String email, long validityInMilliseconds) {
        Claims claims = Jwts.claims().setSubject(email);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }

    public String createProfileAccessToken(String email, Long profileId) {
        Claims claims = Jwts.claims().setSubject(email);
        claims.put("profileId", profileId);
        claims.put("type", "PROFILE");

        return createTokenWithClaims(claims, jwtProperties.getAccessTokenValidityInMilliseconds());
    }

    public String createProfileRefreshToken(String email, Long profileId) {
        Claims claims = Jwts.claims().setSubject(email);
        claims.put("profileId", profileId);
        claims.put("type", "PROFILE");

        return createTokenWithClaims(claims, jwtProperties.getRefreshTokenValidityInMilliseconds());
    }

    private String createTokenWithClaims(Claims claims, long validityInMilliseconds) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = getClaims(token);
        UserDetails userDetails = new CustomUserDetails(claims.getSubject());
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.info("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
    }

    public boolean isProfileToken(String token) {
        return "PROFILE".equals(getClaims(token).get("type", String.class));
    }

    public Long getProfileId(String token) {
        return getClaims(token).get("profileId", Long.class);
    }

    public String createAppToken(String clientId, Long profileId) {
        Claims claims = Jwts.claims()
            .setAudience(clientId)
            .setSubject(profileId.toString());
            
        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(new Date())
            .setExpiration(new Date(new Date().getTime() + jwtProperties.getAppTokenValidityInMilliseconds()))
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();
    }
    
    public boolean validateAppToken(String token, String clientId) {
        try {
            Claims claims = getClaims(token);
            return claims.getAudience().equals(clientId);
        } catch (Exception e) {
            return false;
        }
    }
}