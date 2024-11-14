package com.forrrest.common.security.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;

import com.forrrest.common.security.exception.InvalidTokenException;
import com.forrrest.common.security.token.TokenProvider;
import com.forrrest.common.security.token.TokenType;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@ExtendWith(MockitoExtension.class)
class AbstractTokenFilterTest {
    @Mock
    private TokenProvider tokenProvider;
    
    @Mock
    private HttpServletRequest request;
    
    @Mock
    private HttpServletResponse response;
    
    @Mock
    private FilterChain filterChain;

    private TestTokenFilter tokenFilter;

    @BeforeEach
    void setUp() {
        tokenFilter = new TestTokenFilter(tokenProvider, new String[]{"/api/test/"});
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_WithValidToken_ShouldSetAuthentication() throws ServletException, IOException {
        // given
        String token = "valid.test.token";
        Authentication mockAuth = mock(Authentication.class);
        
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(tokenProvider.validateToken(token)).thenReturn(true);
        when(tokenProvider.validateTokenType(token, TokenType.USER_ACCESS)).thenReturn(true);
        when(tokenProvider.getAuthentication(token)).thenReturn(mockAuth);
        
        // when
        tokenFilter.doFilterInternal(request, response, filterChain);
        
        // then
        verify(filterChain).doFilter(request, response);
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isEqualTo(mockAuth);
    }

    @Test
    void doFilterInternal_WithInvalidToken_ShouldNotSetAuthentication() throws ServletException, IOException {
        // given
        String token = "invalid.test.token";
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(tokenProvider.validateToken(token)).thenThrow(new InvalidTokenException());
        
        // when
        tokenFilter.doFilterInternal(request, response, filterChain);
        
        // then
        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilterInternal_WithInvalidTokenType_ShouldNotSetAuthentication() throws ServletException, IOException {
        // given
        String token = "valid.test.token";
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(tokenProvider.validateToken(token)).thenReturn(true);
        when(tokenProvider.validateTokenType(token, TokenType.USER_ACCESS)).thenReturn(false);
        
        // when
        tokenFilter.doFilterInternal(request, response, filterChain);
        
        // then
        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilterInternal_WithoutAuthorizationHeader_ShouldNotSetAuthentication() throws ServletException, IOException {
        // given
        when(request.getHeader("Authorization")).thenReturn(null);
        
        // when
        tokenFilter.doFilterInternal(request, response, filterChain);
        
        // then
        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilterInternal_WithInvalidAuthorizationHeader_ShouldNotSetAuthentication() throws ServletException, IOException {
        // given
        when(request.getHeader("Authorization")).thenReturn("InvalidFormat token");
        
        // when
        tokenFilter.doFilterInternal(request, response, filterChain);
        
        // then
        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void shouldNotFilter_WithMatchingPath_ShouldReturnFalse() {
        // given
        when(request.getServletPath()).thenReturn("/api/test/something");
        
        // when
        boolean result = tokenFilter.shouldNotFilter(request);
        
        // then
        assertThat(result).isFalse();
    }

    @Test
    void shouldNotFilter_WithNonMatchingPath_ShouldReturnTrue() {
        // given
        when(request.getServletPath()).thenReturn("/api/other/something");
        
        // when
        boolean result = tokenFilter.shouldNotFilter(request);
        
        // then
        assertThat(result).isTrue();
    }

    // Test implementation of AbstractTokenFilter
    private static class TestTokenFilter extends AbstractTokenFilter {
        public TestTokenFilter(TokenProvider tokenProvider, String[] pathPatterns) {
            super(tokenProvider, pathPatterns);
        }

        @Override
        protected TokenType getExpectedTokenType() {
            return TokenType.USER_ACCESS;
        }
    }
}
