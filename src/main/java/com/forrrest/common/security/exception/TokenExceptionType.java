package com.forrrest.common.security.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum TokenExceptionType {
    EXPIRED("토큰이 만료되었습니다"),
    INVALID_SIGNATURE("유효하지 않은 토큰 서명입니다"),
    INVALID_TOKEN("잘못된 토큰입니다"),
    UNSUPPORTED_TOKEN("지원하지 않는 토큰입니다"),
    WRONG_TYPE("잘못된 토큰 타입입니다"),
    EMPTY_CLAIMS("토큰 클레임이 비어있습니다");

    private final String message;
}