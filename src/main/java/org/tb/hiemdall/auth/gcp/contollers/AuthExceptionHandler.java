package org.tb.hiemdall.auth.gcp.contollers;

import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.POST_LOGIN_COOKIE;
import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.STATE_COOKIE;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.tb.hiemdall.auth.exception.AuthFlowException;
import org.tb.hiemdall.auth.exception.CsrfMismatchException;
import org.tb.hiemdall.auth.exception.EmailUnverifiedException;
import org.tb.hiemdall.auth.exception.GoogleTokenExchangeFailedException;
import org.tb.hiemdall.auth.exception.IdTokenMalformedException;
import org.tb.hiemdall.auth.exception.LoginCancelledException;
import org.tb.hiemdall.auth.utilities.CookieCreator;
import org.tb.hiemdall.endpoints.GoogleAuthRequestController;

/**
 * Translates OAuth-flow failures thrown by {@link
 * org.tb.hiemdall.endpoints.GoogleAuthRequestController} into a 302 redirect back to the owning
 * app's registered {@code post-auth-redirect}, carrying {@code #error=<code>&error_description=
 * <msg>} in the URL fragment (never query — error details stay out of server logs on the SPA side).
 *
 * <p>The post-auth URL is recovered from the {@code POST_LOGIN_COOKIE} set during {@code /start}
 * (value shape: {@code "appId|url"}). If the cookie is missing — e.g. a direct hit on {@code
 * /callback} or an expired flow — we fall back to a bare {@code /login} redirect so the browser
 * still lands on something sensible.
 */
@ControllerAdvice(assignableTypes = GoogleAuthRequestController.class)
public class AuthExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthExceptionHandler.class);
    private static final String FALLBACK_PATH = "/login";

    @Autowired CookieCreator cookieCreator;

    @ExceptionHandler(LoginCancelledException.class)
    ResponseEntity<Void> onCancelled(LoginCancelledException e, HttpServletRequest req) {
        if ("access_denied".equals(e.errorCode())) {
            log.info("Login cancelled by user");
        } else {
            log.warn("Google OAuth returned error [{}]", e.errorCode());
        }
        return redirect(req, e.errorCode(), e.getMessage());
    }

    @ExceptionHandler({CsrfMismatchException.class, EmailUnverifiedException.class})
    ResponseEntity<Void> onUserOrCsrfIssue(AuthFlowException e, HttpServletRequest req) {
        log.warn("Auth flow rejected [{}]: {}", e.errorCode(), e.getMessage());
        return redirect(req, e.errorCode(), e.getMessage());
    }

    @ExceptionHandler({GoogleTokenExchangeFailedException.class, IdTokenMalformedException.class})
    ResponseEntity<Void> onUpstreamFailure(AuthFlowException e, HttpServletRequest req) {
        log.error("Auth flow upstream failure [{}]: {}", e.errorCode(), e.getMessage(), e);
        return redirect(req, e.errorCode(), "upstream token exchange failed");
    }

    /** Catch-all so unexpected failures still land back on the SPA instead of a stacktrace page. */
    @ExceptionHandler(Exception.class)
    ResponseEntity<Void> onUnknown(Exception e, HttpServletRequest req) {
        log.error("Auth flow failed with unexpected exception: {}", e.getMessage(), e);
        return redirect(req, "internal_error", "unexpected error");
    }

    private ResponseEntity<Void> redirect(HttpServletRequest req, String code, String description) {
        String postAuthUrl = extractPostAuthUrl(req);
        String fragment =
                "error="
                        + URLEncoder.encode(code, StandardCharsets.UTF_8)
                        + "&error_description="
                        + URLEncoder.encode(
                                description == null ? "" : description, StandardCharsets.UTF_8);
        URI target =
                URI.create((postAuthUrl == null ? FALLBACK_PATH : postAuthUrl) + "#" + fragment);

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(target)
                .header(
                        HttpHeaders.SET_COOKIE,
                        cookieCreator.clearedOauthCookie(STATE_COOKIE).toString())
                .header(
                        HttpHeaders.SET_COOKIE,
                        cookieCreator.clearedOauthCookie(POST_LOGIN_COOKIE).toString())
                .build();
    }

    /** Reads POST_LOGIN_COOKIE and returns the URL portion (after the first {@code '|'}). */
    private static String extractPostAuthUrl(HttpServletRequest req) {
        if (req == null || req.getCookies() == null) return null;
        for (Cookie c : req.getCookies()) {
            if (POST_LOGIN_COOKIE.equals(c.getName())) {
                String v = c.getValue();
                if (v == null || v.isBlank()) return null;
                int idx = v.indexOf('|');
                return idx > 0 ? v.substring(idx + 1) : v;
            }
        }
        return null;
    }
}
