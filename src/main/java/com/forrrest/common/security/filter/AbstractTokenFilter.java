package com.forrrest.common.security.filter;

import java.io.IOException;
import java.util.Arrays;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.forrrest.common.security.exception.TokenException;
import com.forrrest.common.security.token.TokenProvider;
import com.forrrest.common.security.token.TokenType;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public abstract class AbstractTokenFilter extends OncePerRequestFilter {
    private final TokenProvider tokenProvider;
    private final String[] pathPatterns;

    protected AbstractTokenFilter(TokenProvider tokenProvider, String[] pathPatterns) {
        this.tokenProvider = tokenProvider;
        this.pathPatterns = pathPatterns;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        try {
            String token = resolveToken(request);
            if (StringUtils.hasText(token) &&
                tokenProvider.validateToken(token) &&
                tokenProvider.validateTokenType(token, getExpectedTokenType())) {

                Authentication auth = tokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
            filterChain.doFilter(request, response);
        } catch (TokenException e) {
            SecurityContextHolder.clearContext();
            filterChain.doFilter(request, response);
        }
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return Arrays.stream(pathPatterns)
            .noneMatch(path::startsWith);
    }

    protected abstract TokenType getExpectedTokenType();
}