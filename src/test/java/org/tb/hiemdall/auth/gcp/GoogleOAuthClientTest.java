package org.tb.hiemdall.auth.gcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.tb.hiemdall.auth.exception.GoogleAuthRevokedException;
import org.tb.hiemdall.auth.exception.UpstreamUnavailableException;
import org.tb.hiemdall.auth.gcp.configs.GoogleOAuthProperties;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

class GoogleOAuthClientTest {

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

    private GoogleOAuthClient client;
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new GoogleOAuthClient(props, builder);
    }

    @Test
    void refreshReturnsNewAccessToken() {
        server.expect(requestTo(TOKEN_URI))
                .andExpect(method(HttpMethod.POST))
                .andRespond(
                        withSuccess(
                                "{\"access_token\":\"new-at\",\"expires_in\":3600,"
                                        + "\"token_type\":\"Bearer\"}",
                                MediaType.APPLICATION_JSON));

        OAuthTokenResponse resp = client.refresh("refresh-token");

        assertThat(resp.accessToken()).isEqualTo("new-at");
        assertThat(resp.expiresIn()).isEqualTo(3600L);
        server.verify();
    }

    @Test
    void invalidGrantMapsToRevoked() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(
                        withStatus(HttpStatus.BAD_REQUEST)
                                .contentType(MediaType.APPLICATION_JSON)
                                .body("{\"error\":\"invalid_grant\"}"));

        assertThatThrownBy(() -> client.refresh("stale"))
                .isInstanceOf(GoogleAuthRevokedException.class)
                .hasMessageContaining("invalid_grant");
    }

    @Test
    void otherClientErrorMapsToUpstream() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(
                        withStatus(HttpStatus.BAD_REQUEST)
                                .contentType(MediaType.APPLICATION_JSON)
                                .body("{\"error\":\"invalid_client\"}"));

        assertThatThrownBy(() -> client.refresh("t"))
                .isInstanceOf(UpstreamUnavailableException.class);
    }

    @Test
    void serverErrorMapsToUpstream() {
        server.expect(requestTo(TOKEN_URI)).andRespond(withServerError());

        assertThatThrownBy(() -> client.refresh("t"))
                .isInstanceOf(UpstreamUnavailableException.class);
    }

    // NOTE: refresh()'s `catch (Exception e)` swallows the domain exception it
    // threw internally and rewraps with "Google /token unreachable". Cause carries
    // the original "missing access_token" message. Assertions reflect this — fix
    // in source by narrowing the outer catch.
    @Test
    void missingAccessTokenMapsToUpstream() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> client.refresh("t"))
                .isInstanceOf(UpstreamUnavailableException.class)
                .hasRootCauseInstanceOf(UpstreamUnavailableException.class)
                .hasStackTraceContaining("missing access_token");
    }
}
