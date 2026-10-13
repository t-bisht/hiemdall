package org.tb.hiemdall.auth.refresh;

/**
 * Stable error codes returned by {@code POST /internal/auth/google/refresh}. Consumers branch on
 * {@link #code()}; {@link #description()} is fixed hiemdall-authored text for humans and may
 * change.
 */
public enum RefreshErrorCode {
    INVALID_REQUEST("invalid_request", "app and refresh_token are required"),
    UNKNOWN_APP("unknown_app", "app is not registered with hiemdall"),
    REAUTH_REQUIRED(
            "reauth_required",
            "Google refresh token is expired or revoked; the user must sign in again"),
    UPSTREAM_UNAVAILABLE(
            "upstream_unavailable", "Google token endpoint is unavailable; retry with backoff"),
    INTERNAL_ERROR("internal_error", "something went wrong");

    private final String code;
    private final String description;

    RefreshErrorCode(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String code() {
        return code;
    }

    public String description() {
        return description;
    }
}
