package org.tb.hiemdall.auth.records;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Generic OAuth 2.0 / OpenID Connect token endpoint response.
 *
 * <p>Shape defined by RFC 6749 §5.1 (OAuth 2.0) plus OIDC Core §3.1.3.3 for {@code id_token}.
 * Compatible with Google, Okta, Auth0, Azure AD, Apple, and other OIDC providers. Non-OIDC
 * providers (e.g. Facebook, X, GitHub) return a subset — absent fields deserialize as {@code null}.
 *
 * <p>{@code @JsonIgnoreProperties(ignoreUnknown = true)} tolerates provider-specific extras (e.g.
 * GitHub's {@code refresh_token_expires_in}, Azure's {@code ext_expires_in}) without failing.
 *
 * @param accessToken short-lived bearer token
 * @param refreshToken long-lived; only returned on initial exchange (provider-dependent flags)
 * @param idToken OIDC JWT with user identity claims; null for non-OIDC providers
 * @param expiresIn access token lifetime in seconds
 * @param scope space-separated list of granted scopes
 * @param tokenType typically {@code "Bearer"}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OAuthTokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("id_token") String idToken,
        @JsonProperty("expires_in") Long expiresIn,
        @JsonProperty("scope") String scope,
        @JsonProperty("token_type") String tokenType) {

    @Override
    public String toString() {
        return "OAuthTokenResponse{"
                + "accessToken="
                + mask(accessToken)
                + ", refreshToken="
                + mask(refreshToken)
                + ", idToken="
                + mask(idToken)
                + ", expiresIn="
                + expiresIn
                + ", scope="
                + scope
                + ", tokenType="
                + tokenType
                + '}';
    }

    private static String mask(String token) {
        if (token == null) return "null";
        if (token.isEmpty()) return "<empty>";
        if (token.length() <= 8) return "****";
        return token.substring(0, 4) + "****" + token.substring(token.length() - 4);
    }
}
