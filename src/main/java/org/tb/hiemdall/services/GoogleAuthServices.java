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
import org.tb.hiemdall.auth.HiemdallAuthOrchestrator;
import org.tb.hiemdall.auth.records.AuthCallBackRecord;
import org.tb.hiemdall.auth.records.HiemdallAuthResponseRecord;
import org.tb.hiemdall.auth.records.InitAuthRecord;
import org.tb.hiemdall.auth.utilities.CookieCreator;
import org.tb.hiemdall.spring.RegisteredAppsConfig.RegisteredApp;

@Service
public class GoogleAuthServices {

    private static final Logger log = LoggerFactory.getLogger(GoogleAuthServices.class);

    @Resource
    @Qualifier("gcpauthorca")
    HiemdallAuthOrchestrator authOrchestrator;

    @Autowired CookieCreator cookieCreator;

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
            ResponseCookie postLoginCookie =
                    cookieCreator.shortLivedOauthCookie(
                            POST_LOGIN_COOKIE, authStartRecord.postRedirectURL());

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

    public ResponseEntity<Void> handleAuthCallback(AuthCallBackRecord callbackEntities) {

        HiemdallAuthResponseRecord responseRecord =
                authOrchestrator.handleAuthCallBack(callbackEntities);

        String redirectPath = responseRecord.redirectPath();

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(redirectPath))
                .header(
                        HttpHeaders.SET_COOKIE,
                        cookieCreator.clearedOauthCookie(STATE_COOKIE).toString())
                .header(
                        HttpHeaders.SET_COOKIE,
                        cookieCreator.clearedOauthCookie(POST_LOGIN_COOKIE).toString())
                .build();
    }
}
