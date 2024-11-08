package com.forrrest.common.security.config;

import java.util.EnumMap;
import java.util.Map;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import com.forrrest.common.security.token.TokenType;

@ConfigurationProperties(prefix = "token")
@Component
@Getter @Setter
public class TokenProperties {
    private String secret;
    private Map<TokenType, Long> validity = new EnumMap<>(TokenType.class);
}