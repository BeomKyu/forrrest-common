package com.forrrest.common.security.token;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.Authentication;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Base64;
import java.security.Key;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.forrrest.common.TestConfig;
import com.forrrest.common.security.authentication.UserTokenAuthentication;
import com.forrrest.common.security.exception.ExpiredTokenException;
import com.forrrest.common.security.exception.InvalidSignatureException;
import com.forrrest.common.security.exception.InvalidTokenException;
import com.forrrest.common.security.exception.TokenException;
import com.forrrest.common.security.exception.TokenExceptionType;
import com.forrrest.common.security.userdetails.CustomUserDetails;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@SpringBootTest(classes = TestConfig.class)
class TokenProviderTest {
    @Autowired
    private TokenProvider tokenProvider;

    @Test
    void createToken_ShouldGenerateValidToken() {
        // given
        String subject = "test-user";
        Map<String, Object> claims = Map.of(
            "username", "testuser",
            "roles", List.of("USER")
        );

        // when
        String token = tokenProvider.createToken(subject, TokenType.USER_ACCESS, claims);

        // then
        assertThat(tokenProvider.validateToken(token)).isTrue();
        assertThat(tokenProvider.validateTokenType(token, TokenType.USER_ACCESS)).isTrue();

        Claims parsedClaims = tokenProvider.getClaims(token);
        assertThat(parsedClaims.getSubject()).isEqualTo(subject);
        assertThat(parsedClaims.get("username")).isEqualTo("testuser");
        assertThat(parsedClaims.get("roles")).isEqualTo(List.of("USER"));
    }

    @Test
    void getAuthentication_ShouldReturnCorrectAuthenticationType() {
        // given
        String token = tokenProvider.createToken("test-user", TokenType.USER_ACCESS, Map.of(
            "username", "testuser",
            "roles", List.of("USER")
        ));

        // when
        Authentication auth = tokenProvider.getAuthentication(token);

        // then
        assertThat(auth).isInstanceOf(UserTokenAuthentication.class);
        assertThat(auth.getPrincipal()).isInstanceOf(CustomUserDetails.class);
    }

    @Test
    void validateToken_ShouldThrowExpiredTokenException() {
        // given
        String token = createExpiredToken();

        // when & then
        assertThatThrownBy(() -> tokenProvider.validateToken(token))
            .isInstanceOf(ExpiredTokenException.class)
            .hasFieldOrPropertyWithValue("type", TokenExceptionType.EXPIRED);
    }

    @Test
    void validateToken_ShouldThrowInvalidSignatureException() {
        // given
        String validToken = tokenProvider.createToken("test-user", TokenType.USER_ACCESS);
        String tamperedToken = validToken.substring(0, validToken.length() - 5) + "wrong";

        // when & then
        assertThatThrownBy(() -> tokenProvider.validateToken(tamperedToken))
            .isInstanceOf(InvalidSignatureException.class);
    }

    @Test
    void validateToken_ShouldThrowInvalidTokenException() {
        // given
        String invalidToken = "invalid.token.format";

        // when & then
        assertThatThrownBy(() -> tokenProvider.validateToken(invalidToken))
            .isInstanceOf(InvalidTokenException.class)
            .hasFieldOrPropertyWithValue("type", TokenExceptionType.INVALID_TOKEN);
    }

    @Test
    void validateTokenType_ShouldThrowWrongTypeException() {
        // given
        String token = Jwts.builder()
            .setSubject("test-user")
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000))
            .claim("tokenType", "INVALID_TYPE") // 잘못된 토큰 타입
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();

        // when & then
        assertThatThrownBy(() -> tokenProvider.validateTokenType(token, TokenType.USER_ACCESS))
            .isInstanceOf(TokenException.class)
            .hasFieldOrPropertyWithValue("type", TokenExceptionType.WRONG_TYPE);
    }

    @Test
    void getAuthentication_ShouldThrowEmptyClaimsException() {
        // given
        String token = tokenProvider.createToken("test-user", TokenType.USER_ACCESS, Map.of(
            "username", "testuser"
            // roles claim 누락
        ));

        // when & then
        assertThatThrownBy(() -> tokenProvider.getAuthentication(token))
            .isInstanceOf(TokenException.class)
            .hasFieldOrPropertyWithValue("type", TokenExceptionType.EMPTY_CLAIMS);
    }

    private String createExpiredToken() {
        Date now = new Date();
        Date expiration = new Date(now.getTime() - 1000); // 이미 만료된 시간

        return Jwts.builder()
            .setSubject("test-user")
            .setIssuedAt(now)
            .setExpiration(expiration)
            .claim("tokenType", TokenType.USER_ACCESS.name())
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    private Key getSigningKey() {
        // Base64로 인코딩된 시크릿 키
        String secret = "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtbG9uZy1lbm91Z2gtZm9yLWEtdmFsaWQtaHMyNTYtc2lnbmluZy1rZXk=";
        byte[] keyBytes = Base64.getDecoder().decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
