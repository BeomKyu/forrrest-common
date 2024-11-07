package com.forrrest.common.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secret;
    private long accessTokenValidityInMilliseconds = 3600000;  // 1시간
    private long refreshTokenValidityInMilliseconds = 604800000;  // 7일
    private long appTokenValidityInMilliseconds = 2592000000L;  // 30일
}