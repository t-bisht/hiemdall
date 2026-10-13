package org.tb.hiemdall.auth.refresh;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

/**
 * Request body for {@code POST /internal/auth/google/refresh}. The owning app's backend sends its
 * appId plus the Google refresh_token it holds. {@link #toString()} masks the token so it never
 * reaches logs.
 */
public record TokenRefreshRequest(
        @NotBlank String app, @NotBlank @JsonProperty("refresh_token") String refreshToken) {

    @Override
    public String toString() {
        return "TokenRefreshRequest{" + "app=" + app + ", refreshToken=" + mask(refreshToken) + '}';
    }

    private static String mask(String token) {
        if (token == null) return "null";
        if (token.isEmpty()) return "<empty>";
        if (token.length() <= 8) return "****";
        return token.substring(0, 4) + "****" + token.substring(token.length() - 4);
    }
}
