package org.tb.hiemdall.auth.gcp.services;

import jakarta.annotation.Resource;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import org.tb.hiemdall.auth.exception.AuthInitializationException;
import org.tb.hiemdall.auth.gcp.configs.GoogleOAuthProperties;
import org.tb.hiemdall.auth.records.InitAuthRecord;
import org.tb.hiemdall.auth.utilities.OAuthStateGenerator;
import org.tb.hiemdall.spring.RegisteredAppsConfig;

@Service
public class GoogleAuthStartService {

    private static final Logger log = LoggerFactory.getLogger(GoogleAuthStartService.class);

    @Autowired OAuthStateGenerator stateGenerator;

    @Resource
    @Qualifier("appRegister")
    Map<String, RegisteredAppsConfig.RegisteredApp> appRegister;

    @Resource GoogleOAuthProperties props;

    public InitAuthRecord createAuthInitializationRecord(String appID) {
        try {
            String postAuthRedirectURL = appRegister.get(appID).postAuthRedirect();
            String csrfToken = stateGenerator.generate();
            String authUrl = buildGoogleAuthURL(csrfToken);
            return new InitAuthRecord(csrfToken, authUrl, postAuthRedirectURL);
        } catch (Exception e) {
            log.error("auth init failed for appID '{}': {}", appID, e.getMessage(), e);
            throw new AuthInitializationException(
                    "something went wrong initializing authentication", e);
        }
    }

    public String buildGoogleAuthURL(String csrfToken) {
        return UriComponentsBuilder.fromUriString(props.authUri())
                .queryParam("client_id", props.clientId())
                .queryParam("redirect_uri", props.redirectUri())
                .queryParam("response_type", "code")
                .queryParam("scope", String.join(" ", props.scopes()))
                .queryParam("state", csrfToken)
                .queryParam("access_type", props.accessType())
                .queryParam("prompt", props.prompt())
                .queryParam("include_granted_scopes", "true")
                .encode()
                .build()
                .toUriString();
    }
}
