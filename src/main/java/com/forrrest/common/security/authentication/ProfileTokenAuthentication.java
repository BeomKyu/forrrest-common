package com.forrrest.common.security.authentication;

import com.forrrest.common.security.userdetails.CustomUserDetails;

public class ProfileTokenAuthentication extends TokenAuthentication {
    public ProfileTokenAuthentication(CustomUserDetails principal, String credentials) {
        super(principal, credentials);
    }
}