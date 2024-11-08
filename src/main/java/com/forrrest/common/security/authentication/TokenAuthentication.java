package com.forrrest.common.security.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import com.forrrest.common.security.userdetails.CustomUserDetails;

import lombok.Getter;

@Getter
public abstract class TokenAuthentication extends AbstractAuthenticationToken {
    private final CustomUserDetails principal;
    private final String credentials;

    protected TokenAuthentication(CustomUserDetails principal, String credentials) {
        super(principal.getAuthorities());
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }
}