package com.forrrest.common.security.authentication;

import com.forrrest.common.security.userdetails.CustomUserDetails;

public class NonceTokenAuthentication extends TokenAuthentication {
    public NonceTokenAuthentication(CustomUserDetails principal, String credentials) {
        super(principal, credentials);
    }
}