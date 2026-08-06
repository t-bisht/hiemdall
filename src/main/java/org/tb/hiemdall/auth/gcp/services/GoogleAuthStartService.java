package org.tb.hiemdall.auth.gcp.services;

import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.*;

import java.net.URI;
import java.util.Map;

import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;
import org.tb.hiemdall.auth.config.GoogleOAuthProperties;
import org.tb.hiemdall.auth.records.InitAuthRecord;
import org.tb.hiemdall.auth.utilities.CookieCreator;
import org.tb.hiemdall.auth.utilities.OAuthStateGenerator;
import org.tb.hiemdall.spring.RegisteredAppsConfig;

@Service
public class GoogleAuthStartService {


    @Autowired
    OAuthStateGenerator stateGenerator;

    @Autowired
    CookieCreator cookieCreator;

    @Resource
    @Qualifier("appRegister")
    Map<String, RegisteredAppsConfig.RegisteredApp> appRegister;


    @Resource
    GoogleOAuthProperties props;


    public InitAuthRecord createAuthInitializationRecord(String appID) {
        String postAuthRedirectURL = appRegister.get(appID).postAuthRedirect();
        String csrfToken = stateGenerator.generate();
        String authUrl = buildGoogleAuthURL(csrfToken, /* forceConsent= */ true);
        return new InitAuthRecord(csrfToken, authUrl, postAuthRedirectURL);
    }


    public String buildGoogleAuthURL(String csrfToken, boolean forceConsent) {
        UriComponentsBuilder b =
                UriComponentsBuilder.fromUriString(props.authUri())
                        .queryParam("client_id", props.clientId())
                        .queryParam("redirect_uri", props.redirectUri())
                        .queryParam("response_type", "code")
                        .queryParam("scope", String.join(" ", props.scopes()))
                        .queryParam("state", csrfToken)
                        .queryParam("access_type", "offline")
                        .queryParam("include_granted_scopes", "true");
        if (forceConsent) {
            b.queryParam("prompt", "consent");
        }
        return b.encode().build().toUriString();
    }

//    public ResponseEntity<Void> startGoogleAuthService(String redirect) {
//
//
//        ResponseCookie stateCookie = cookieCreator.shortLivedOauthCookie(STATE_COOKIE, state);
//        ResponseCookie postLoginCookie =
//                cookieCreator.shortLivedOauthCookie(POST_LOGIN_COOKIE, resolvedRedirect);
//
//        return ResponseEntity.status(HttpStatus.FOUND)
//                .location(URI.create(authUrl))
//                .header(HttpHeaders.SET_COOKIE, stateCookie.toString())
//                .header(HttpHeaders.SET_COOKIE, postLoginCookie.toString())
//                .build();
//    }
}
