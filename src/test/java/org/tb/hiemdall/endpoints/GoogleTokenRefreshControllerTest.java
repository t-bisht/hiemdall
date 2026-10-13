package org.tb.hiemdall.endpoints;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.tb.hiemdall.auth.exception.GoogleAuthRevokedException;
import org.tb.hiemdall.auth.gcp.GoogleOAuthClient;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

/**
 * End-to-end slice: real {@code InternalAuthFilter} + Spring Security headers + Spring MVC +
 * controller + service, with the Google client mocked.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(
        properties = {
            "app.internal.svc-token=test-internal-token",
            "app.google.client-id=stub",
            "app.google.client-secret=stub",
            "app.google.redirect-uri=http://localhost/cb",
            "app.registered-apps.stash.app-name=stash",
            "app.registered-apps.stash.post-auth-redirect=http://localhost/return"
        })
class GoogleTokenRefreshControllerTest {

    private static final String TOKEN = "test-internal-token";
    private static final String URL = "/internal/auth/google/refresh";
    private static final String BODY = "{\"app\":\"stash\",\"refresh_token\":\"rt-123\"}";

    @Autowired MockMvc mvc;
    @MockBean GoogleOAuthClient googleOAuthClient;

    @Test
    void happyPathReturnsSnakeCaseTokenBody() throws Exception {
        when(googleOAuthClient.refresh("rt-123"))
                .thenReturn(new OAuthTokenResponse("at", null, null, 3599L, "openid", "Bearer"));

        mvc.perform(
                        post(URL)
                                .header("X-Internal-Auth", TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("at"))
                .andExpect(jsonPath("$.expires_in").value(3599))
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }

    @Test
    void responseIsNotCacheable() throws Exception {
        when(googleOAuthClient.refresh("rt-123"))
                .thenReturn(new OAuthTokenResponse("at", null, null, 3599L, "openid", "Bearer"));

        mvc.perform(
                        post(URL)
                                .header("X-Internal-Auth", TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(BODY))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(header().string("Pragma", "no-cache"));
    }

    @Test
    void missingHeaderReturns401() throws Exception {
        mvc.perform(post(URL).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(googleOAuthClient);
    }

    @Test
    void wrongTokenReturns401() throws Exception {
        mvc.perform(
                        post(URL)
                                .header("X-Internal-Auth", "nope")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(BODY))
                .andExpect(status().isUnauthorized());

        verifyNoInteractions(googleOAuthClient);
    }

    @Test
    void invalidGrantReturns401ReauthRequired() throws Exception {
        when(googleOAuthClient.refresh(anyString()))
                .thenThrow(new GoogleAuthRevokedException("Google returned invalid_grant"));

        mvc.perform(
                        post(URL)
                                .header("X-Internal-Auth", TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("reauth_required"))
                .andExpect(jsonPath("$.reauth_url").exists());
    }

    @Test
    void unknownAppReturns400() throws Exception {
        mvc.perform(
                        post(URL)
                                .header("X-Internal-Auth", TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"app\":\"nope\",\"refresh_token\":\"rt-123\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unknown_app"));
    }
}
