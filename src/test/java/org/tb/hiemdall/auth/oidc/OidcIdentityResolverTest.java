package org.tb.hiemdall.auth.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.tb.hiemdall.auth.exception.EmailUnverifiedException;
import org.tb.hiemdall.auth.exception.IdTokenMalformedException;
import org.tb.hiemdall.auth.identity.oidc.GoogleOIDCIdentityResolver;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

class OidcIdentityResolverTest {

    private final GoogleOIDCIdentityResolver resolver =
            new GoogleOIDCIdentityResolver(new ObjectMapper());

    @Test
    void resolvesClaimsFromVerifiedIdToken() {
        String idToken =
                buildIdToken(
                        "{\"sub\":\"sub-123\",\"email\":\"tb@example.com\","
                                + "\"email_verified\":true,\"name\":\"TB\","
                                + "\"picture\":\"https://pic/tb\"}");

        IdentityClaims claims = resolver.resolve(tokenResponse(idToken));

        assertThat(claims)
                .isEqualTo(new IdentityClaims("sub-123", "tb@example.com", "TB", "https://pic/tb"));
    }

    @Test
    void rejectsWhenIdTokenAbsent() {
        assertThatThrownBy(() -> resolver.resolve(tokenResponse(null)))
                .isInstanceOf(IdTokenMalformedException.class)
                .hasMessageContaining("missing id_token");
    }

    @Test
    void rejectsWhenEmailVerifiedFalse() {
        String idToken =
                buildIdToken(
                        "{\"sub\":\"s\",\"email\":\"a@b\",\"email_verified\":false,\"name\":\"n\"}");
        assertThatThrownBy(() -> resolver.readClaims(idToken))
                .isInstanceOf(EmailUnverifiedException.class);
    }

    @Test
    void rejectsWhenEmailVerifiedMissing() {
        String idToken = buildIdToken("{\"sub\":\"s\",\"email\":\"a@b\",\"name\":\"n\"}");
        assertThatThrownBy(() -> resolver.readClaims(idToken))
                .isInstanceOf(EmailUnverifiedException.class);
    }

    @Test
    void rejectsMalformedTokenShape() {
        assertThatThrownBy(() -> resolver.readClaims("only-two.parts"))
                .isInstanceOf(IdTokenMalformedException.class)
                .hasMessageContaining("3 dot-separated parts");
    }

    @Test
    void rejectsMissingSub() {
        String idToken = buildIdToken("{\"email\":\"a@b\",\"email_verified\":true}");
        assertThatThrownBy(() -> resolver.readClaims(idToken))
                .isInstanceOf(IdTokenMalformedException.class)
                .hasMessageContaining("sub");
    }

    private static OAuthTokenResponse tokenResponse(String idToken) {
        return new OAuthTokenResponse(
                "access", "refresh", idToken, 3600L, "openid email", "Bearer");
    }

    private static String buildIdToken(String payloadJson) {
        String header = base64Url("{\"alg\":\"RS256\",\"kid\":\"g1\"}");
        String payload = base64Url(payloadJson);
        return header + "." + payload + ".fake-sig-not-verified";
    }

    private static String base64Url(String s) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}
