package org.tb.hiemdall.auth.gcp.contollers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.POST_LOGIN_COOKIE;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.tb.hiemdall.auth.exception.CsrfMismatchException;
import org.tb.hiemdall.auth.exception.EmailUnverifiedException;
import org.tb.hiemdall.auth.exception.GoogleTokenExchangeFailedException;
import org.tb.hiemdall.auth.exception.IdTokenMalformedException;
import org.tb.hiemdall.auth.exception.LoginCancelledException;
import org.tb.hiemdall.auth.utilities.CookieCreator;

class AuthExceptionHandlerTest {

    private AuthExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new AuthExceptionHandler();
        // Minimal stub — handler only ever asks it for cleared cookies.
        CookieCreator stub =
                new CookieCreator() {
                    @Override
                    public ResponseCookie clearedOauthCookie(String name) {
                        return ResponseCookie.from(name, "").maxAge(0).build();
                    }
                };
        ReflectionTestUtils.setField(handler, "cookieCreator", stub);
    }

    @Test
    void userCancelRedirectsToPostAuthWithAccessDeniedFragment() {
        ResponseEntity<Void> resp =
                handler.onCancelled(
                        new LoginCancelledException("access_denied"),
                        requestWithPostLogin("stash|http://localhost:5173/auth/return"));
        assertFragmentRedirect(resp, "http://localhost:5173/auth/return", "access_denied");
    }

    @Test
    void csrfMismatchRedirectsWithCsrfMismatchCode() {
        ResponseEntity<Void> resp =
                handler.onUserOrCsrfIssue(
                        new CsrfMismatchException("boom"),
                        requestWithPostLogin("stash|http://localhost:5173/auth/return"));
        assertFragmentRedirect(resp, "http://localhost:5173/auth/return", "csrf_mismatch");
    }

    @Test
    void emailUnverifiedRedirectsWithEmailUnverified() {
        ResponseEntity<Void> resp =
                handler.onUserOrCsrfIssue(
                        new EmailUnverifiedException("boom"),
                        requestWithPostLogin("stash|http://localhost:5173/auth/return"));
        assertFragmentRedirect(resp, "http://localhost:5173/auth/return", "email_unverified");
    }

    @Test
    void tokenExchangeFailureRedirectsWithTokenExchangeFailedCode() {
        ResponseEntity<Void> resp =
                handler.onUpstreamFailure(
                        new GoogleTokenExchangeFailedException("boom"),
                        requestWithPostLogin("stash|http://localhost:5173/auth/return"));
        assertFragmentRedirect(resp, "http://localhost:5173/auth/return", "token_exchange_failed");
    }

    @Test
    void idTokenMalformedRedirectsWithTokenExchangeFailedCode() {
        ResponseEntity<Void> resp =
                handler.onUpstreamFailure(
                        new IdTokenMalformedException("boom"),
                        requestWithPostLogin("stash|http://localhost:5173/auth/return"));
        assertFragmentRedirect(resp, "http://localhost:5173/auth/return", "token_exchange_failed");
    }

    @Test
    void unknownExceptionRedirectsWithInternalError() {
        ResponseEntity<Void> resp =
                handler.onUnknown(
                        new RuntimeException("boom"),
                        requestWithPostLogin("stash|http://localhost:5173/auth/return"));
        assertFragmentRedirect(resp, "http://localhost:5173/auth/return", "internal_error");
    }

    @Test
    void missingPostLoginCookieFallsBackToLoginPath() {
        ResponseEntity<Void> resp =
                handler.onUserOrCsrfIssue(
                        new CsrfMismatchException("boom"), new MockHttpServletRequest());
        assertFragmentRedirect(resp, "/login", "csrf_mismatch");
    }

    @Test
    void redirectClearsOauthCookies() {
        ResponseEntity<Void> resp =
                handler.onUserOrCsrfIssue(
                        new CsrfMismatchException("boom"), new MockHttpServletRequest());
        assertThat(resp.getHeaders().get(HttpHeaders.SET_COOKIE)).hasSize(2);
    }

    private static MockHttpServletRequest requestWithPostLogin(String value) {
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.setCookies(new Cookie(POST_LOGIN_COOKIE, value));
        return req;
    }

    private static void assertFragmentRedirect(
            ResponseEntity<Void> resp, String base, String errCode) {
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(resp.getHeaders().getLocation()).isNotNull();
        String location = resp.getHeaders().getLocation().toString();
        assertThat(location).startsWith(base + "#error=" + errCode);
        assertThat(location).contains("&error_description=");
    }
}
