package org.tb.hiemdall.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.tb.hiemdall.auth.exception.GoogleAuthRevokedException;
import org.tb.hiemdall.auth.exception.UpstreamUnavailableException;
import org.tb.hiemdall.auth.gcp.GoogleOAuthClient;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;
import org.tb.hiemdall.auth.refresh.TokenRefreshRequest;
import org.tb.hiemdall.spring.RegisteredAppsConfig.RegisteredApp;

@ExtendWith(MockitoExtension.class)
class GoogleTokenRefreshServiceTest {

    private static final String RT = "1//0g-refresh-token-value";

    @Mock GoogleOAuthClient googleOAuthClient;

    private GoogleTokenRefreshService service;

    @BeforeEach
    void setUp() {
        service = new GoogleTokenRefreshService();
        ReflectionTestUtils.setField(service, "googleOAuthClient", googleOAuthClient);
        ReflectionTestUtils.setField(
                service,
                "appRegister",
                Map.of("stash", new RegisteredApp("stash", "http://localhost/return")));
    }

    @Test
    void happyPathReturnsTokens() {
        OAuthTokenResponse tokens =
                new OAuthTokenResponse("at", null, "idt", 3599L, "openid", "Bearer");
        when(googleOAuthClient.refresh(RT)).thenReturn(tokens);

        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest("stash", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody()).isSameAs(tokens);
        assertThat(((OAuthTokenResponse) resp.getBody()).refreshToken()).isNull();
    }

    @Test
    void rotatedRefreshTokenIsPassedThrough() {
        OAuthTokenResponse tokens =
                new OAuthTokenResponse("at", "rotated-rt", null, 3599L, "openid", "Bearer");
        when(googleOAuthClient.refresh(RT)).thenReturn(tokens);

        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest("stash", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(((OAuthTokenResponse) resp.getBody()).refreshToken()).isEqualTo("rotated-rt");
    }

    @Test
    void invalidGrantReturns401ReauthRequired() {
        when(googleOAuthClient.refresh(RT))
                .thenThrow(new GoogleAuthRevokedException("Google returned invalid_grant"));

        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest("stash", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(body(resp))
                .containsEntry("error", "reauth_required")
                .containsEntry("reauth_url", "/auth/google/start?app=stash");
    }

    @Test
    void upstreamFailureReturns502() {
        when(googleOAuthClient.refresh(RT))
                .thenThrow(new UpstreamUnavailableException("Google /token unreachable", null));

        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest("stash", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_GATEWAY);
        assertThat(body(resp)).containsEntry("error", "upstream_unavailable");
    }

    @Test
    void unexpectedExceptionReturns500WithGenericBody() {
        when(googleOAuthClient.refresh(RT)).thenThrow(new IllegalStateException("boom-secret"));

        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest("stash", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(body(resp)).containsEntry("error", "internal_error");
        assertThat(body(resp).values()).noneMatch(v -> v.contains("boom-secret"));
    }

    @Test
    void blankRefreshTokenReturns400() {
        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest("stash", "  "));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(resp)).containsEntry("error", "invalid_request");
        verifyNoInteractions(googleOAuthClient);
    }

    @Test
    void oversizedRefreshTokenReturns400() {
        String oversized = "a".repeat(GoogleTokenRefreshService.MAX_REFRESH_TOKEN_LENGTH + 1);

        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest("stash", oversized));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(resp)).containsEntry("error", "invalid_request");
        verifyNoInteractions(googleOAuthClient);
    }

    @Test
    void blankAppReturns400() {
        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest(" ", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(resp)).containsEntry("error", "invalid_request");
        verifyNoInteractions(googleOAuthClient);
    }

    @Test
    void unknownAppReturns400() {
        ResponseEntity<?> resp = service.refresh(new TokenRefreshRequest("otherapp", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(resp)).containsEntry("error", "unknown_app");
        verifyNoInteractions(googleOAuthClient);
    }

    @Test
    void errorBodiesNeverContainRefreshToken() {
        assertNoToken(service.refresh(new TokenRefreshRequest("otherapp", RT)));
        assertNoToken(service.refresh(new TokenRefreshRequest("", RT)));

        when(googleOAuthClient.refresh(RT))
                .thenThrow(new GoogleAuthRevokedException("revoked " + RT))
                .thenThrow(new UpstreamUnavailableException("down " + RT, null))
                .thenThrow(new IllegalStateException("boom " + RT));
        assertNoToken(service.refresh(new TokenRefreshRequest("stash", RT)));
        assertNoToken(service.refresh(new TokenRefreshRequest("stash", RT)));
        assertNoToken(service.refresh(new TokenRefreshRequest("stash", RT)));
    }

    private static void assertNoToken(ResponseEntity<?> resp) {
        assertThat(resp.getStatusCode().is2xxSuccessful()).isFalse();
        assertThat(body(resp).values()).noneMatch(v -> v.contains(RT));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> body(ResponseEntity<?> resp) {
        return (Map<String, String>) resp.getBody();
    }
}
