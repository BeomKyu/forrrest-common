package com.forrrest.common;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

import com.forrrest.common.security.config.TokenProperties;

@SpringBootConfiguration
@ComponentScan(basePackages = "com.forrrest.common")
@EnableConfigurationProperties(TokenProperties.class)
public class TestConfig {
}
