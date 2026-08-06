package org.tb.hiemdall.auth.gcp.contollers;

import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.POST_LOGIN_COOKIE;
import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.STATE_COOKIE;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.tb.hiemdall.auth.gcp.services.GoogleAuthCallbackService;
import org.tb.hiemdall.auth.gcp.services.GoogleAuthStartService;

/**
 * Browser-facing endpoints for the Google OAuth flow + logout.
 *
 * <p>Implements spec §4.1 ({@code /google/start}), §4.2 happy path ({@code /google/callback}), and
 * §4.4 ({@code /logout}). Failure branches from §4.3 are handled by {@link AuthExceptionHandler}.
 * Session-JWT refresh is not implemented — spec picks Pattern A (full re-login on expiry, §4.10).
 *
 * <p>Cookies:
 *
 * <ul>
 *   <li>{@code kk_oauth_state} — set at {@code /start}, consumed at {@code /callback} (CSRF)
 *   <li>{@code kk_oauth_post_login} — set at {@code /start}, consumed at {@code /callback} (route
 *       user back to intended SPA path)
 *   <li>{@code kk_session} — set at {@code /callback} (24 h RS256 JWT; the actual session token)
 *   <li>{@code kk_csrf} — set at {@code /callback} (double-submit CSRF token, non-HttpOnly so the
 *       SPA can echo it back on unsafe methods like logout)
 * </ul>
 */

public class GoogleAuthController {

    private static final Logger log = LoggerFactory.getLogger(GoogleAuthController.class);

    private final GoogleAuthCallbackService authCallBackService;
    private final GoogleAuthStartService authStartService;

    public GoogleAuthController(
            ) {

        this.authCallBackService = authCallBackService;
        this.authStartService = authStartService;
    }

    // ─── §4.1 — /google/start ───────────────────────────────────────────────

    /**
     * Kicks off Google OAuth. Generates a fresh CSRF state, builds Google's authorization URL, sets
     * two short-lived cookies, returns a 302 to Google.
     */


    // ─── §4.2 — /google/callback (happy path) ──────────────────────────────

    /**
     * Handles Google's post-consent redirect. Verifies CSRF state, exchanges code for tokens,
     * extracts identity, persists Google tokens, mints session JWT, sets session + CSRF cookies,
     * 302s browser back to the SPA path stored at /start.
     */
    @GetMapping("/google/callback")
    public ResponseEntity<Void> handleGoogleCallback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            @CookieValue(name = STATE_COOKIE, required = false) String stateCookie,
            @CookieValue(name = POST_LOGIN_COOKIE, required = false) String postLoginCookie) {

        return authCallBackService.handleCallback(error, state, stateCookie, code, postLoginCookie);
    }
}
