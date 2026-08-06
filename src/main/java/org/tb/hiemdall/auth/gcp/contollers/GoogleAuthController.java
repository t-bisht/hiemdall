package org.tb.hiemdall.auth.gcp.contollers;

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
//
public class GoogleAuthController {
    //
    //    private static final Logger log = LoggerFactory.getLogger(GoogleAuthController.class);
    //
    //
    //    private final GoogleAuthStartService authStartService;
    //

    //    // ─── §4.1 — /google/start ───────────────────────────────────────────────
    //
    //    /**
    //     * Kicks off Google OAuth. Generates a fresh CSRF state, builds Google's authorization
    // URL, sets
    //     * two short-lived cookies, returns a 302 to Google.
    //     */
    //
    //
    //    // ─── §4.2 — /google/callback (happy path) ──────────────────────────────
    //
    //    /**
    //     * Handles Google's post-consent redirect. Verifies CSRF state, exchanges code for tokens,
    //     * extracts identity, persists Google tokens, mints session JWT, sets session + CSRF
    // cookies,
    //     * 302s browser back to the SPA path stored at /start.
    //     */
}
