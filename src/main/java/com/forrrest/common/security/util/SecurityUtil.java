package com.forrrest.common.security.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.forrrest.common.exception.CustomException;
import com.forrrest.common.exception.ErrorCode;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityUtil {
    
    public Long getCurrentProfileId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.debug("Authentication: {}", authentication);
        
        if (authentication == null || authentication.getPrincipal() == null) {
            log.debug("Authentication or Principal is null");
            throw new CustomException(ErrorCode.UNAUTHORIZED);
        }
        
        try {
            log.debug("Principal class: {}", authentication.getPrincipal().getClass());
            log.debug("Principal: {}", authentication.getPrincipal());
            
            Claims claims = (Claims) authentication.getPrincipal();
            Long profileId = claims.get("profileId", Long.class);
            log.debug("ProfileId: {}", profileId);
            
            return profileId;
        } catch (Exception e) {
            log.error("Error in getCurrentProfileId", e);
            throw new CustomException(ErrorCode.UNAUTHORIZED);
        }
    }
}