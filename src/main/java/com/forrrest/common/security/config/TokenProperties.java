package com.forrrest.common.security.config;

import java.util.*;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import com.forrrest.common.security.token.TokenType;

@ConfigurationProperties(prefix = "token")
@Component
@Getter @Setter
public class TokenProperties {
    private Map<String, Key> keys = new HashMap<>();
    private String currentKeyId;

    @Getter
    @Setter
    public static class Key {
        /** JWT 헤더의 kid 필드에 매핑될 Key ID */
        private String id;
        /** HMAC 알고리즘용 비밀 키(인코딩된 문자열) */
        private String secret;
    }

    private Map<TokenType, Long> validity = new EnumMap<>(TokenType.class);
}