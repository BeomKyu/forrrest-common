package com.forrrest.common.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode {
    // Common Errors
    INVALID_INPUT_VALUE(400, "Invalid input value"),
    INVALID_TYPE_VALUE(400, "Invalid type value"),
    UNAUTHORIZED(401, "Unauthorized access"),
    FORBIDDEN(403, "Forbidden access"),
    NOT_FOUND(404, "Resource not found"),
    METHOD_NOT_ALLOWED(405, "Method not allowed"),
    INTERNAL_SERVER_ERROR(500, "Internal server error");

    private final int status;
    private final String message;
}