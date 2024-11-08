package com.forrrest.common.security.authentication;

import com.forrrest.common.security.userdetails.CustomUserDetails;

public class UserTokenAuthentication extends TokenAuthentication {
    public UserTokenAuthentication(CustomUserDetails principal, String credentials) {
        super(principal, credentials);
    }
}