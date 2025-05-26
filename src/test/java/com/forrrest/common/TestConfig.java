package com.forrrest.common;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

import com.forrrest.common.security.config.TokenProperties;
import org.springframework.test.context.TestPropertySource;

@SpringBootConfiguration
@ComponentScan(basePackages = "com.forrrest.common")
@EnableConfigurationProperties(TokenProperties.class)
@TestPropertySource(locations = "src/test/resources/application.yml")
public class TestConfig {
}
