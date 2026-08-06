package org.tb.hiemdall.auth.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.tb.hiemdall.auth.exception.IdTokenMalformedException;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

/**
 * Resolves a provider's token response into provider-neutral {@link IdentityClaims}.
 *
 * <p>Two implementation styles:
 *
 * <ul>
 *   <li>OIDC providers (Google, Okta, Auth0, Apple, Azure) — decode {@code id_token} JWT payload.
 *   <li>Non-OIDC providers (Facebook, GitHub, X) — call provider's userinfo endpoint with {@code
 *       access_token}.
 * </ul>
 *
 * <p>Callers hold this interface, not concrete impls. Multiple provider beans coexist behind
 * {@code @Qualifier} or provider-keyed selection at the callback layer.
 */
public interface IdentityResolver {

    IdentityClaims resolve(OAuthTokenResponse tokens);

    /**
     * Decodes the payload segment of a signed JWT ({@code <header>.<payload>.<signature>}) into a
     * JSON tree. Shared by all OIDC-style resolvers.
     *
     * @throws IdTokenMalformedException if the token isn't a well-formed three-part JWT or the
     *     payload isn't valid base64url / JSON
     */
    static JsonNode decodePayload(ObjectMapper mapper, String idToken) {
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new IdTokenMalformedException(
                    "id_token must have 3 dot-separated parts, got " + parts.length);
        }
        try {
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            return mapper.readTree(new String(payloadBytes, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new IdTokenMalformedException("id_token payload is not valid base64url", e);
        } catch (Exception e) {
            throw new IdTokenMalformedException("id_token payload is not valid JSON", e);
        }
    }
}
