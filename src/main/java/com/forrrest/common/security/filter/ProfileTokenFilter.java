package com.forrrest.common.security.filter;

import java.io.IOException;
import java.util.Collections;

import com.forrrest.common.security.jwt.JwtProvider;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@Component
@RequiredArgsConstructor
public class ProfileTokenFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private static final String PROFILE_HEADER = "Profile-Authorization";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        log.debug("ProfileTokenFilter - Request URI: {}", request.getRequestURI());
        String token = resolveToken(request);
        log.debug("ProfileTokenFilter - Token: {}", token);

        if (token != null && jwtProvider.validateToken(token)) {
            log.debug("Token is valid");
            if (jwtProvider.isProfileToken(token)) {
                log.debug("Token is profile token");
                Long profileId = jwtProvider.getProfileId(token);
                log.debug("ProfileId from token: {}", profileId);

                Claims claims = jwtProvider.getClaims(token);
                SecurityContextHolder.getContext()
                    .setAuthentication(new UsernamePasswordAuthenticationToken(claims, "", Collections.emptyList()));
                log.debug("Authentication set in SecurityContext");
            }
        } else {
            log.debug("No valid token found");
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        log.debug("Authorization header: {}", bearerToken);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}