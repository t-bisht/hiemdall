package org.tb.hiemdall.auth.gcp.clients;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.tb.hiemdall.auth.exception.GoogleTokenExchangeFailedException;
import org.tb.hiemdall.auth.gcp.configs.GoogleOAuthProperties;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

@Service
/*
- Responsible for making OAUTH TOKEN exchange post user authentication
- This would return refresh , acceess , JWT and other auth info
 */
public class GoogleTokenExchangeClient {

    @Autowired GoogleOAuthProperties props;

    @Autowired
    @Qualifier("basicRestClient")
    RestClient restClient;

    private static final Logger log = LoggerFactory.getLogger(GoogleTokenExchangeClient.class);

    /**
     * Exchanges an authorization code for Google's token set (access + refresh + id_token).
     *
     * @param code the {@code ?code=...} value Google sent to our callback
     * @return parsed token response
     * @throws GoogleTokenExchangeFailedException if Google responds non-2xx or the request fails
     */
    public OAuthTokenResponse exchangeCode(String code) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("code", code);
        form.add("client_id", props.clientId());
        form.add("client_secret", props.clientSecret());
        form.add(
                "redirect_uri",
                props.redirectUri()); // used only for validation that this is the same
        // application for which it has authenticated the user
        // the above is also the URL that is registered with google
        form.add("grant_type", "authorization_code");

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

            if (body == null || body.accessToken() == null || body.idToken() == null) {
                throw new GoogleTokenExchangeFailedException(
                        "Google /token response missing access_token or id_token");
            }
            return body;
        } catch (RestClientResponseException e) {
            log.warn(
                    "Google /token exchange failed: status={}, body={}",
                    e.getStatusCode(),
                    e.getResponseBodyAsString());
            throw new GoogleTokenExchangeFailedException(
                    "Google /token responded " + e.getStatusCode(), e);
        } catch (Exception e) {
            log.warn("Google /token exchange failed: {}", e.getMessage());
            throw new GoogleTokenExchangeFailedException("Google /token unreachable", e);
        }
    }
}
