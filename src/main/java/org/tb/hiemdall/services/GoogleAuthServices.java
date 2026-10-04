package org.tb.hiemdall.services;

import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.POST_LOGIN_COOKIE;
import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.STATE_COOKIE;

import jakarta.annotation.Resource;
import java.net.URI;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import org.tb.hiemdall.auth.HiemdallAuthOrchestrator;
import org.tb.hiemdall.auth.handoff.HandoffStore;
import org.tb.hiemdall.auth.handoff.HandoffStoreFullException;
import org.tb.hiemdall.auth.records.*;
import org.tb.hiemdall.auth.utilities.CookieCreator;
import org.tb.hiemdall.spring.RegisteredAppsConfig.RegisteredApp;

@Service
public class GoogleAuthServices {

    private static final Logger log = LoggerFactory.getLogger(GoogleAuthServices.class);

    @Resource
    @Qualifier("gcpauthorca")
    HiemdallAuthOrchestrator authOrchestrator;

    @Autowired CookieCreator cookieCreator;

    @Autowired HandoffStore handoffStore;

    @Resource
    @Qualifier("appRegister")
    Map<String, RegisteredApp> appRegister;

    public ResponseEntity<Map<String, String>> startGoogleAuthService(String appID) {

        if (appID == null || appID.isBlank() || !appRegister.containsKey(appID)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "invalid or unknown appID"));
        }

        try {
            InitAuthRecord authStartRecord = authOrchestrator.initiateAuthProcess(appID);

            ResponseCookie stateCookie =
                    cookieCreator.shortLivedOauthCookie(STATE_COOKIE, authStartRecord.csrfToken());
            // Stash BOTH the appId and the post-auth URL inside the post-login cookie value so the
            // callback can re-derive which app it is handing tokens off to. Format: "appId|url".
            ResponseCookie postLoginCookie =
                    cookieCreator.shortLivedOauthCookie(
                            POST_LOGIN_COOKIE, appID + "|" + authStartRecord.postRedirectURL());

            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(authStartRecord.authRedirectURL()))
                    .header(HttpHeaders.SET_COOKIE, stateCookie.toString())
                    .header(HttpHeaders.SET_COOKIE, postLoginCookie.toString())
                    .build();
        } catch (Exception e) {
            log.error("startGoogleAuthService failed for appID '{}': {}", appID, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "something went wrong starting authentication"));
        }
    }

    /**
     * Handles Google's redirect-back. Runs the orchestrator, parks the resulting token bundle in
     * the handoff store under a fresh opaque code, and 302s the browser to the registered post-auth
     * URL carrying only {@code ?handoff=<code>} — the raw Google tokens never touch the browser.
     */
    public ResponseEntity<Void> handleAuthCallback(AuthCallBackRecord callbackEntities) {

        HiemdallAuthResponseRecord responseRecord =
                authOrchestrator.handleAuthCallBack(callbackEntities);

        String[] parts = splitPostLogin(responseRecord.redirectPath());
        String appId = parts[0];
        String postAuthRedirect = parts[1];

        String handoffCode;
        try {
            handoffCode =
                    handoffStore.put(appId, responseRecord.tokens(), responseRecord.identity());
        } catch (HandoffStoreFullException e) {
            log.error("handoff store full; rejecting callback for appId '{}'", appId);
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .header(
                            HttpHeaders.SET_COOKIE,
                            cookieCreator.clearedOauthCookie(STATE_COOKIE).toString())
                    .header(
                            HttpHeaders.SET_COOKIE,
                            cookieCreator.clearedOauthCookie(POST_LOGIN_COOKIE).toString())
                    .build();
        }

        URI redirectWithHandoff =
                UriComponentsBuilder.fromUriString(postAuthRedirect)
                        .queryParam("handoff", handoffCode)
                        .build()
                        .toUri();

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(redirectWithHandoff)
                .header(
                        HttpHeaders.SET_COOKIE,
                        cookieCreator.clearedOauthCookie(STATE_COOKIE).toString())
                .header(
                        HttpHeaders.SET_COOKIE,
                        cookieCreator.clearedOauthCookie(POST_LOGIN_COOKIE).toString())
                .build();
    }

    /**
     * Post-login cookie carries {@code appId|postAuthRedirect}. Legacy / malformed values (no pipe)
     * are treated as the URL alone, with appId derived by scanning {@code appRegister} — this keeps
     * the callback usable through a format rollover.
     */
    private String[] splitPostLogin(String value) {
        if (value == null) {
            return new String[] {"", ""};
        }
        int idx = value.indexOf('|');
        if (idx > 0) {
            return new String[] {value.substring(0, idx), value.substring(idx + 1)};
        }
        return new String[] {resolveAppIdByUrl(value), value};
    }

    private String resolveAppIdByUrl(String url) {
        for (Map.Entry<String, RegisteredApp> e : appRegister.entrySet()) {
            if (e.getValue().postAuthRedirect().equals(url)) {
                return e.getKey();
            }
        }
        return "";
    }
}
