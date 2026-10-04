package org.tb.hiemdall.auth.gcp.clients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.tb.hiemdall.auth.exception.GoogleTokenExchangeFailedException;
import org.tb.hiemdall.auth.gcp.configs.GoogleOAuthProperties;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

class GoogleTokenExchangeClientTest {

    private static final String TOKEN_URI = "https://oauth2.googleapis.com/token";

    private final GoogleOAuthProperties props =
            new GoogleOAuthProperties(
                    "client-abc",
                    "secret-xyz",
                    "https://accounts.google.com/o/oauth2/v2/auth",
                    TOKEN_URI,
                    "http://localhost:3000/callback",
                    List.of("openid", "email"),
                    "offline",
                    "consent");

    private GoogleTokenExchangeClient client;
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        RestClient restClient = builder.build();

        client = new GoogleTokenExchangeClient();
        ReflectionTestUtils.setField(client, "props", props);
        ReflectionTestUtils.setField(client, "restClient", restClient);
    }

    @Test
    void exchangeCodePostsFormAndParsesTokens() {
        server.expect(requestTo(TOKEN_URI))
                .andExpect(method(HttpMethod.POST))
                .andExpect(
                        header("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("code=auth-code")))
                .andExpect(
                        content()
                                .string(
                                        org.hamcrest.Matchers.containsString(
                                                "client_id=client-abc")))
                .andExpect(
                        content()
                                .string(
                                        org.hamcrest.Matchers.containsString(
                                                "grant_type=authorization_code")))
                .andRespond(
                        withSuccess(
                                "{\"access_token\":\"at\",\"refresh_token\":\"rt\","
                                        + "\"id_token\":\"idt\",\"expires_in\":3600,"
                                        + "\"scope\":\"openid email\",\"token_type\":\"Bearer\"}",
                                MediaType.APPLICATION_JSON));

        OAuthTokenResponse resp = client.exchangeCode("auth-code");

        assertThat(resp.accessToken()).isEqualTo("at");
        assertThat(resp.refreshToken()).isEqualTo("rt");
        assertThat(resp.idToken()).isEqualTo("idt");
        assertThat(resp.expiresIn()).isEqualTo(3600L);
        server.verify();
    }

    // NOTE: exchangeCode's `catch (Exception e)` swallows the domain exception it
    // threw internally and rewraps with "Google /token unreachable". Cause carries
    // the original "missing ..." message. Assertions reflect this — fix in source
    // by narrowing the outer catch.

    @Test
    void throwsWhenAccessTokenMissing() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withSuccess("{\"id_token\":\"idt\"}", MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> client.exchangeCode("code"))
                .isInstanceOf(GoogleTokenExchangeFailedException.class)
                .hasRootCauseInstanceOf(GoogleTokenExchangeFailedException.class)
                .hasStackTraceContaining("missing access_token");
    }

    @Test
    void throwsWhenIdTokenMissing() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withSuccess("{\"access_token\":\"at\"}", MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> client.exchangeCode("code"))
                .isInstanceOf(GoogleTokenExchangeFailedException.class)
                .hasRootCauseInstanceOf(GoogleTokenExchangeFailedException.class);
    }

    @Test
    void wrapsClientErrorAsExchangeFailure() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(
                        withStatus(HttpStatus.BAD_REQUEST).body("{\"error\":\"invalid_grant\"}"));

        assertThatThrownBy(() -> client.exchangeCode("code"))
                .isInstanceOf(GoogleTokenExchangeFailedException.class)
                .hasMessageContaining("400");
    }

    @Test
    void wrapsServerErrorAsExchangeFailure() {
        server.expect(requestTo(TOKEN_URI)).andRespond(withServerError());

        assertThatThrownBy(() -> client.exchangeCode("code"))
                .isInstanceOf(GoogleTokenExchangeFailedException.class);
    }
}
