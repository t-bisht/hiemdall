package org.tb.hiemdall.auth.identity.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import org.tb.hiemdall.auth.exception.EmailUnverifiedException;
import org.tb.hiemdall.auth.exception.IdTokenMalformedException;
import org.tb.hiemdall.auth.identity.IdentityResolver;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

/**
 * OIDC-standard {@link IdentityResolver} — decodes an {@code id_token} JWT payload.
 *
 * <p>An {@code id_token} is a signed JWT with three base64url-encoded parts joined by dots: {@code
 * <header>.<payload>.<signature>}. This resolver decodes only the payload and enforces {@code
 * email_verified == true}.
 *
 * <p>Compatible with any OIDC provider that emits standard OIDC Core §5.1 claims — Google, Okta,
 * Auth0, Apple. Azure AD needs a dedicated resolver (does not emit {@code email_verified}, uses
 * {@code preferred_username}/{@code upn} instead of {@code email} for personal accounts).
 *
 * <p>Deliberately skips signature verification: the token arrived back-channel over TLS during the
 * server-side code exchange. Verifying its signature adds no security against a browser MITM (the
 * TLS channel already provides that) and would require fetching + caching provider JWKS.
 *
 * <p>If we ever accept id_tokens from the browser (e.g. Google One-Tap on the SPA), reintroduce
 * RS256 verification against the provider's JWKS.
 */
@Component("googleOIDC")
public class GoogleOIDCIdentityResolver implements IdentityResolver {

    private final ObjectMapper mapper;

    public GoogleOIDCIdentityResolver(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    public IdentityClaims resolve(OAuthTokenResponse tokens) {
        if (tokens.idToken() == null) {
            throw new IdTokenMalformedException("token response missing id_token");
        }
        return readClaims(tokens.idToken());
    }

    /**
     * Parses the id_token and returns the identity claims.
     *
     * @throws IdTokenMalformedException if the token isn't a well-formed three-part JWT or the
     *     payload isn't valid JSON
     * @throws EmailUnverifiedException if the {@code email_verified} claim is false or missing
     */
    public IdentityClaims readClaims(String idToken) {
        JsonNode payload = IdentityResolver.decodePayload(mapper, idToken);

        if (!payload.path("email_verified").asBoolean(false)) {
            throw new EmailUnverifiedException("id_token email_verified is false or missing");
        }

        return new IdentityClaims(
                requireText(payload, "sub"),
                requireText(payload, "email"),
                payload.path("name").asText(""),
                payload.path("picture").asText(""));
    }

    private static String requireText(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull() || value.asText().isEmpty()) {
            throw new IdTokenMalformedException(
                    "id_token payload missing required field: " + field);
        }
        return value.asText();
    }
}
