package com.forrrest.common;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import com.forrrest.common.security.config.JwtProperties;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class CommonConfig {
}