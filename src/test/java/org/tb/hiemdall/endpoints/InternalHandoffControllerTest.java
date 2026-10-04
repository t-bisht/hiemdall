package org.tb.hiemdall.endpoints;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.tb.hiemdall.auth.handoff.HandoffEntry;
import org.tb.hiemdall.auth.handoff.HandoffStore;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

/**
 * End-to-end slice: real {@code InternalAuthFilter} + Spring MVC + controller, with the store
 * mocked. Covers T1.2a's four required cases: happy path, 401 w/o header, 404 on expired, 404 on
 * wrong-app.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(
        properties = {
            "app.internal.svc-token=test-internal-token",
            "app.google.client-id=stub",
            "app.google.client-secret=stub",
            "app.google.redirect-uri=http://localhost/cb"
        })
class InternalHandoffControllerTest {

    private static final String TOKEN = "test-internal-token";

    @Autowired MockMvc mvc;
    @MockBean HandoffStore handoffStore;

    @Test
    void happyPathReturnsGoogleTokenBundle() throws Exception {
        OAuthTokenResponse tokens =
                new OAuthTokenResponse("at", "rt", "idt", 3600L, "openid", "Bearer");
        when(handoffStore.consume(eq("stash"), eq("code-123")))
                .thenReturn(
                        new HandoffEntry(
                                "stash",
                                tokens,
                                new IdentityClaims("sub", "u@e.com", "U", null),
                                Instant.MAX));

        mvc.perform(
                        post("/internal/auth/exchange")
                                .header("X-Internal-Auth", TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"app\":\"stash\",\"handoff\":\"code-123\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("at"))
                .andExpect(jsonPath("$.refresh_token").value("rt"))
                .andExpect(jsonPath("$.id_token").value("idt"));
    }

    @Test
    void missingHeaderReturns401() throws Exception {
        mvc.perform(
                        post("/internal/auth/exchange")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"app\":\"stash\",\"handoff\":\"code-123\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongTokenReturns401() throws Exception {
        mvc.perform(
                        post("/internal/auth/exchange")
                                .header("X-Internal-Auth", "nope")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"app\":\"stash\",\"handoff\":\"code-123\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void expiredOrUnknownCodeReturns404() throws Exception {
        when(handoffStore.consume(eq("stash"), eq("expired"))).thenReturn(null);

        mvc.perform(
                        post("/internal/auth/exchange")
                                .header("X-Internal-Auth", TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"app\":\"stash\",\"handoff\":\"expired\"}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void wrongAppReturns404() throws Exception {
        // Store returns null for mismatched app — controller translates to 404 identically.
        when(handoffStore.consume(eq("otherapp"), eq("code-123"))).thenReturn(null);

        mvc.perform(
                        post("/internal/auth/exchange")
                                .header("X-Internal-Auth", TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"app\":\"otherapp\",\"handoff\":\"code-123\"}"))
                .andExpect(status().isNotFound());
    }
}
