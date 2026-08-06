package org.tb.hiemdall.auth.gcp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.tb.hiemdall.auth.exception.GoogleAuthRevokedException;
import org.tb.hiemdall.auth.exception.UpstreamUnavailableException;
import org.tb.hiemdall.auth.gcp.configs.GoogleOAuthProperties;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

/**
 * HTTP client for Google's OAuth token endpoint. Handles both:
 *
 * <ul>
 *   <li>{@link #exchangeCode(String)} — initial code-for-tokens exchange (spec §4.2)
 *   <li>{@link #refresh(String)} — swap refresh_token for a new access_token (spec §4.7)
 * </ul>
 *
 * <p>Uses Spring's {@link RestClient} (synchronous, Spring 6.1+). Timeouts and retries rely on
 * defaults for now — tune when we see real Google flakiness.
 */
@Component
public class GoogleOAuthClient {

    private static final Logger log = LoggerFactory.getLogger(GoogleOAuthClient.class);

    private final GoogleOAuthProperties props;
    private final RestClient restClient;

    public GoogleOAuthClient(GoogleOAuthProperties props, RestClient.Builder builder) {
        this.props = props;
        this.restClient = builder.build();
    }

    /**
     * Uses a stored refresh_token to mint a fresh access_token. Google usually keeps the same
     * refresh_token but occasionally rotates it — the caller must persist whatever comes back.
     *
     * @param refreshToken the previously-stored Google refresh_token
     * @return parsed token response ({@code access_token} + {@code expires_in} always populated;
     *     {@code refresh_token} present only when rotated)
     * @throws GoogleAuthRevokedException on {@code 400 invalid_grant} — user revoked or Google
     *     invalidated the grant; recovery requires full re-consent
     * @throws UpstreamUnavailableException on other Google errors or network failure
     */
    public OAuthTokenResponse refresh(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", props.clientId());
        form.add("client_secret", props.clientSecret());
        form.add("refresh_token", refreshToken);
        form.add("grant_type", "refresh_token");

        try {
            OAuthTokenResponse body =
                    restClient
                            .post()
                            .uri(props.tokenUri())
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .accept(MediaType.APPLICATION_JSON)
                            .body(form)
                            .retrieve()
                            .body(OAuthTokenResponse.class);
            if (body == null || body.accessToken() == null) {
                throw new UpstreamUnavailableException(
                        "Google /token refresh missing access_token", null);
            }
            return body;
        } catch (RestClientResponseException e) {
            // Google returns 400 { error: "invalid_grant" } for revoked / invalid refresh tokens.
            String responseBody = e.getResponseBodyAsString();
            if (e.getStatusCode().value() == 400 && responseBody.contains("invalid_grant")) {
                throw new GoogleAuthRevokedException("Google returned invalid_grant on refresh");
            }
            log.warn(
                    "Google /token refresh failed: status={}, body={}",
                    e.getStatusCode(),
                    responseBody);
            throw new UpstreamUnavailableException(
                    "Google /token refresh returned " + e.getStatusCode(), e);
        } catch (GoogleAuthRevokedException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Google /token refresh failed: {}", e.getMessage());
            throw new UpstreamUnavailableException("Google /token unreachable", e);
        }
    }
}
