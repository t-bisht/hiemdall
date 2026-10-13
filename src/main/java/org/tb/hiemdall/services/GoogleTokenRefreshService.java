package org.tb.hiemdall.services;

import jakarta.annotation.Resource;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import org.tb.hiemdall.auth.exception.GoogleAuthRevokedException;
import org.tb.hiemdall.auth.exception.UpstreamUnavailableException;
import org.tb.hiemdall.auth.gcp.GoogleOAuthClient;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;
import org.tb.hiemdall.auth.refresh.RefreshErrorCode;
import org.tb.hiemdall.auth.refresh.TokenRefreshRequest;
import org.tb.hiemdall.spring.RegisteredAppsConfig.RegisteredApp;

/**
 * Swaps an app-held Google refresh_token for a fresh access_token on behalf of a registered app.
 * Serves {@code POST /internal/auth/google/refresh}. Stateless: makes exactly one Google call per
 * request and stores nothing.
 *
 * <p>Security: refresh tokens, access tokens and Google error bodies never appear in logs or error
 * responses. Error bodies carry only a stable {@link RefreshErrorCode}.
 */
@Service
public class GoogleTokenRefreshService {

    private static final Logger log = LoggerFactory.getLogger(GoogleTokenRefreshService.class);
    static final int MAX_REFRESH_TOKEN_LENGTH = 2048;

    @Autowired GoogleOAuthClient googleOAuthClient;

    @Resource
    @Qualifier("appRegister")
    Map<String, RegisteredApp> appRegister;

    public ResponseEntity<?> refresh(TokenRefreshRequest request) {
        if (request == null
                || request.app() == null
                || request.app().isBlank()
                || request.refreshToken() == null
                || request.refreshToken().isBlank()
                || request.refreshToken().length() > MAX_REFRESH_TOKEN_LENGTH) {
            return error(HttpStatus.BAD_REQUEST, RefreshErrorCode.INVALID_REQUEST);
        }
        String app = request.app();
        if (!appRegister.containsKey(app)) {
            log.info("token refresh rejected: unknown app '{}'", app);
            return error(HttpStatus.BAD_REQUEST, RefreshErrorCode.UNKNOWN_APP);
        }

        try {
            OAuthTokenResponse tokens = googleOAuthClient.refresh(request.refreshToken());
            log.info(
                    "token refresh succeeded for app '{}', refreshTokenRotated={}",
                    app,
                    tokens.refreshToken() != null);
            return ResponseEntity.ok(tokens);
        } catch (GoogleAuthRevokedException e) {
            log.info("token refresh for app '{}' requires re-auth: {}", app, e.getMessage());
            Map<String, String> body = errorBody(RefreshErrorCode.REAUTH_REQUIRED);
            body.put("reauth_url", reauthUrl(app));
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
        } catch (UpstreamUnavailableException e) {
            log.warn("token refresh for app '{}' failed upstream: {}", app, e.getMessage(), e);
            return error(HttpStatus.BAD_GATEWAY, RefreshErrorCode.UPSTREAM_UNAVAILABLE);
        } catch (Exception e) {
            log.error("token refresh for app '{}' failed: {}", app, e.getMessage(), e);
            return error(HttpStatus.INTERNAL_SERVER_ERROR, RefreshErrorCode.INTERNAL_ERROR);
        }
    }

    private static ResponseEntity<Map<String, String>> error(
            HttpStatus status, RefreshErrorCode code) {
        return ResponseEntity.status(status).body(errorBody(code));
    }

    private static Map<String, String> errorBody(RefreshErrorCode code) {
        Map<String, String> body = new HashMap<>();
        body.put("error", code.code());
        body.put("error_description", code.description());
        return body;
    }

    private static String reauthUrl(String app) {
        return UriComponentsBuilder.fromPath("/auth/google/start")
                .queryParam("app", app)
                .encode()
                .toUriString();
    }
}
