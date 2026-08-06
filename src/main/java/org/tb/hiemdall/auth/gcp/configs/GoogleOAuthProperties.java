package org.tb.hiemdall.auth.gcp.configs;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.google")
public record GoogleOAuthProperties(
        @NotBlank String clientId,
        @NotBlank String clientSecret,
        @NotBlank String authUri,
        @NotBlank String tokenUri,
        @NotBlank String redirectUri,
        @NotEmpty List<@NotBlank String> scopes) {}
