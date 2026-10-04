package org.tb.hiemdall.auth.gcp.configs;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Google OAuth client config. {@code accessType} and {@code prompt} default to {@code offline} /
 * {@code consent} — the pair required for Google to return a {@code refresh_token} on every
 * authorize call (otherwise the token is only issued the first time a user consents).
 */
@Validated
@ConfigurationProperties(prefix = "app.google")
public record GoogleOAuthProperties(
        @NotBlank String clientId,
        @NotBlank String clientSecret,
        @NotBlank String authUri,
        @NotBlank String tokenUri,
        @NotBlank String redirectUri,
        @NotEmpty List<@NotBlank String> scopes,
        @NotBlank String accessType,
        @NotBlank String prompt) {

    public GoogleOAuthProperties {
        if (accessType == null || accessType.isBlank()) accessType = "offline";
        if (prompt == null || prompt.isBlank()) prompt = "consent";
    }
}
