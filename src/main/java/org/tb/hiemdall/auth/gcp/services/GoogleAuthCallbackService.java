package org.tb.hiemdall.auth.gcp.services;

import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.POST_LOGIN_COOKIE;
import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.STATE_COOKIE;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.tb.hiemdall.auth.OAuthStateGenerator;
import org.tb.hiemdall.auth.exception.CsrfMismatchException;
import org.tb.hiemdall.auth.exception.LoginCancelledException;
import org.tb.hiemdall.auth.gcp.GoogleOAuthClient;
import org.tb.hiemdall.auth.gcp.IdTokenClaimsReader;
import org.tb.hiemdall.auth.gcp.dto.GoogleTokenResponse;
import org.tb.hiemdall.auth.gcp.dto.IdentityClaims;
import org.tb.hiemdall.security.SessionJwtIssuer;

@Service
public class GoogleAuthCallbackService {

    private static final Logger log = LoggerFactory.getLogger(GoogleAuthCallbackService.class);

    @Autowired GoogleOAuthClient googleClient;

    @Autowired IdTokenClaimsReader idTokenReader;

    @Autowired SessionJwtIssuer jwtIssuer;

    @Autowired OAuthStateGenerator stateGenerator;

    @Autowired RedirectionResolver redirectionResolver;

    @Autowired CookieCreator cookieCreator;

    public ResponseEntity<Void> handleCallback(
            String error, String state, String stateCookie, String code, String postLoginCookie) {

        if (error != null && !error.isBlank()) {
            // Spec §4.3 first branch — user pressed Cancel at Google.
            throw new LoginCancelledException();
        }

        verifyCsrfState(state, stateCookie);

        GoogleTokenResponse tokens = googleClient.exchangeCode(code);
        IdentityClaims identity = idTokenReader.readClaims(tokens.idToken());

        // TODO(user-engine): POST /internal/users/upsert-from-google when user_engine exists.
        log.info(
                "Would upsert user_engine identity for sub={} email={}",
                identity.sub(),
                identity.email());

        String sessionJwt = jwtIssuer.issue(identity, extractScopes(tokens.scope()));
        String csrfToken = stateGenerator.generate();
        String redirectPath = redirectionResolver.resolveRedirect(postLoginCookie);

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(redirectPath))
                .header(HttpHeaders.SET_COOKIE, cookieCreator.sessionCookie(sessionJwt).toString())
                .header(HttpHeaders.SET_COOKIE, cookieCreator.csrfCookie(csrfToken).toString())
                .header(
                        HttpHeaders.SET_COOKIE,
                        cookieCreator.clearedOauthCookie(STATE_COOKIE).toString())
                .header(
                        HttpHeaders.SET_COOKIE,
                        cookieCreator.clearedOauthCookie(POST_LOGIN_COOKIE).toString())
                .build();
    }

    /**
     * CSRF check for the OAuth callback — state param must match state cookie. Constant-time
     * compare to avoid timing-based state exfiltration.
     */
    private static void verifyCsrfState(String stateParam, String stateCookie) {
        if (stateParam == null || stateParam.isBlank()) {
            throw new CsrfMismatchException("state query param missing");
        }
        if (stateCookie == null || stateCookie.isBlank()) {
            throw new CsrfMismatchException("kk_oauth_state cookie missing");
        }
        if (!MessageDigest.isEqual(
                stateParam.getBytes(StandardCharsets.UTF_8),
                stateCookie.getBytes(StandardCharsets.UTF_8))) {
            throw new CsrfMismatchException("state mismatch");
        }
    }

    /** Splits the space-separated Google scope string into a list. */
    private static List<String> extractScopes(String spaceSeparated) {
        if (spaceSeparated == null || spaceSeparated.isBlank()) return List.of();
        return Arrays.stream(spaceSeparated.trim().split("\\s+")).toList();
    }
}
