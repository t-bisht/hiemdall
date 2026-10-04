package org.tb.hiemdall.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.tb.hiemdall.auth.HiemdallAuthOrchestrator;
import org.tb.hiemdall.auth.handoff.HandoffStore;
import org.tb.hiemdall.auth.records.AuthCallBackRecord;
import org.tb.hiemdall.auth.records.HiemdallAuthResponseRecord;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;
import org.tb.hiemdall.auth.utilities.CookieCreator;
import org.tb.hiemdall.spring.RegisteredAppsConfig.RegisteredApp;

/**
 * Verifies the T1.2 handoff contract: callback redirects to the registered post-auth URL with a
 * {@code ?handoff=…} query param and leaks no Google token material in the response.
 */
@ExtendWith(MockitoExtension.class)
class GoogleAuthServicesCallbackHandoffTest {

    @Mock HiemdallAuthOrchestrator orchestrator;
    @Mock HandoffStore handoffStore;
    @Mock CookieCreator cookieCreator;

    private GoogleAuthServices service;

    @BeforeEach
    void setUp() {
        service = new GoogleAuthServices();
        ReflectionTestUtils.setField(service, "authOrchestrator", orchestrator);
        ReflectionTestUtils.setField(service, "handoffStore", handoffStore);
        ReflectionTestUtils.setField(service, "cookieCreator", cookieCreator);
        ReflectionTestUtils.setField(
                service,
                "appRegister",
                Map.of("stash", new RegisteredApp("STASH", "http://localhost:5173/auth/return")));

        // Cleared cookies — we don't care about their content, just that they're present.
        when(cookieCreator.clearedOauthCookie(any()))
                .thenAnswer(inv -> ResponseCookie.from(inv.getArgument(0), "").maxAge(0).build());
    }

    @Test
    void callbackRedirectsToPostAuthUrlWithHandoffAndNoTokenMaterial() {
        OAuthTokenResponse tokens =
                new OAuthTokenResponse(
                        "ya29.secret-access",
                        "1//secret-refresh",
                        "idt.secret",
                        3600L,
                        "openid",
                        "Bearer");
        IdentityClaims identity = new IdentityClaims("sub", "u@e.com", "U", null);
        when(orchestrator.handleAuthCallBack(any()))
                .thenReturn(
                        new HiemdallAuthResponseRecord(
                                tokens,
                                identity,
                                "new-csrf",
                                "stash|http://localhost:5173/auth/return"));
        when(handoffStore.put(eq("stash"), eq(tokens), eq(identity))).thenReturn("opaque-code-xyz");

        AuthCallBackRecord rec =
                new AuthCallBackRecord(
                        null, "s", "s", "code", "stash|http://localhost:5173/auth/return");
        ResponseEntity<Void> resp = service.handleAuthCallback(rec);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(resp.getHeaders().getLocation()).isNotNull();
        String location = resp.getHeaders().getLocation().toString();
        assertThat(location).startsWith("http://localhost:5173/auth/return?handoff=");
        assertThat(location).endsWith("handoff=opaque-code-xyz");

        // Explicitly verify no raw Google-token material anywhere in the redirect URL / headers.
        assertThat(location)
                .doesNotContain("ya29", "1//", "idt.secret", "id_token", "refresh_token");

        // Clear-cookie headers for state + post-login present.
        assertThat(resp.getHeaders().get(HttpHeaders.SET_COOKIE)).hasSize(2);
    }
}
