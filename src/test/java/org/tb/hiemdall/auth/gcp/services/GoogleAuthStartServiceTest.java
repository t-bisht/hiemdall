package org.tb.hiemdall.auth.gcp.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.tb.hiemdall.auth.exception.AuthInitializationException;
import org.tb.hiemdall.auth.gcp.configs.GoogleOAuthProperties;
import org.tb.hiemdall.auth.records.InitAuthRecord;
import org.tb.hiemdall.auth.utilities.OAuthStateGenerator;
import org.tb.hiemdall.spring.RegisteredAppsConfig.RegisteredApp;

@ExtendWith(MockitoExtension.class)
class GoogleAuthStartServiceTest {

    private static final GoogleOAuthProperties PROPS =
            new GoogleOAuthProperties(
                    "client-abc.apps.googleusercontent.com",
                    "secret",
                    "https://accounts.google.com/o/oauth2/v2/auth",
                    "https://oauth2.googleapis.com/token",
                    "http://localhost:3000/api/auth/google/callback",
                    List.of("openid", "email", "profile"),
                    "offline",
                    "consent");

    @Mock OAuthStateGenerator stateGenerator;

    private GoogleAuthStartService service;

    @BeforeEach
    void setUp() {
        service = new GoogleAuthStartService();
        ReflectionTestUtils.setField(service, "props", PROPS);
        ReflectionTestUtils.setField(service, "stateGenerator", stateGenerator);
        ReflectionTestUtils.setField(
                service,
                "appRegister",
                Map.of("kkt", new RegisteredApp("KK", "http://localhost/dashboard")));
    }

    @Test
    void buildsUrlWithAllRequiredOauthParams() {
        String url = service.buildGoogleAuthURL("state-xyz");
        Map<String, String> params = params(url);

        assertThat(url).startsWith("https://accounts.google.com/o/oauth2/v2/auth?");
        assertThat(params)
                .containsEntry("client_id", "client-abc.apps.googleusercontent.com")
                .containsEntry("redirect_uri", "http://localhost:3000/api/auth/google/callback")
                .containsEntry("response_type", "code")
                .containsEntry("scope", "openid email profile")
                .containsEntry("state", "state-xyz")
                .containsEntry("access_type", "offline")
                .containsEntry("prompt", "consent")
                .containsEntry("include_granted_scopes", "true");
    }

    @Test
    void propsControlAccessTypeAndPromptValues() {
        GoogleOAuthProperties custom =
                new GoogleOAuthProperties(
                        "cid",
                        "sec",
                        "https://accounts.google.com/o/oauth2/v2/auth",
                        "https://oauth2.googleapis.com/token",
                        "http://localhost/cb",
                        List.of("openid"),
                        "online",
                        "none");
        GoogleAuthStartService svc = new GoogleAuthStartService();
        ReflectionTestUtils.setField(svc, "props", custom);

        Map<String, String> p = params(svc.buildGoogleAuthURL("s"));
        assertThat(p).containsEntry("access_type", "online").containsEntry("prompt", "none");
    }

    @Test
    void createRecordReturnsCsrfAuthUrlAndPostRedirect() {
        when(stateGenerator.generate()).thenReturn("csrf-42");

        InitAuthRecord rec = service.createAuthInitializationRecord("kkt");

        assertThat(rec.csrfToken()).isEqualTo("csrf-42");
        assertThat(rec.postRedirectURL()).isEqualTo("http://localhost/dashboard");
        assertThat(params(rec.authRedirectURL())).containsEntry("state", "csrf-42");
    }

    @Test
    void unknownAppIdWrappedAsInitializationFailure() {
        assertThatThrownBy(() -> service.createAuthInitializationRecord("unknown"))
                .isInstanceOf(AuthInitializationException.class);
    }

    private static Map<String, String> params(String url) {
        return UriComponentsBuilder.fromUri(URI.create(url))
                .build()
                .getQueryParams()
                .entrySet()
                .stream()
                .collect(
                        Collectors.toMap(
                                Map.Entry::getKey,
                                e ->
                                        URLDecoder.decode(
                                                e.getValue().get(0), StandardCharsets.UTF_8)));
    }
}
