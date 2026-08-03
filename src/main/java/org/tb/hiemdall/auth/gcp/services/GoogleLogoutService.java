package org.tb.hiemdall.auth.gcp.services;

public class GoogleLogoutService {

    // CLASS TO BE  PLANNED OUT

    /*
    // ─── §4.4 — /logout ────────────────────────────────────────────────────

    /**
     * Idempotent client-side sign-out. Double-submit CSRF: the SPA reads the non-HttpOnly
     * {@code kk_csrf} cookie and echoes it as {@code X-CSRF-Token}. auth_engine confirms both
     * halves match. Clears both session cookies; DB untouched (JWTs are stateless).
     *
     * <p>Google refresh_token in {@code login_tokens} is deliberately preserved so the next
     * login on this browser reuses it silently — "logged out" ≠ "disconnected Gmail".
     */
    //    @PostMapping("/logout")
    //    public ResponseEntity<Void> logout(
    //            @CookieValue(name = CSRF_COOKIE, required = false) String csrfCookieValue,
    //            @RequestHeader(name = CSRF_HEADER, required = false) String csrfHeaderValue) {
    //
    //        verifyDoubleSubmitCsrf(csrfCookieValue, csrfHeaderValue);
    //
    //        return ResponseEntity.status(HttpStatus.NO_CONTENT)
    //                .header(HttpHeaders.SET_COOKIE,
    // clearedSessionCookie(SESSION_COOKIE).toString())
    //                .header(HttpHeaders.SET_COOKIE, clearedSessionCookie(CSRF_COOKIE).toString())
    //                .build();
    //    }

    // ─── Helpers ───────────────────────────────────────────────────────────

    /**
     * CSRF check for logout — X-CSRF-Token header must equal kk_csrf cookie value. Both halves
     * required. Constant-time compare.
     */
    //    private static void verifyDoubleSubmitCsrf(String cookie, String header) {
    //        if (cookie == null || cookie.isBlank()) {
    //            throw new CsrfMismatchException("kk_csrf cookie missing");
    //        }
    //        if (header == null || header.isBlank()) {
    //            throw new CsrfMismatchException("X-CSRF-Token header missing");
    //        }
    //        if (!MessageDigest.isEqual(
    //                cookie.getBytes(StandardCharsets.UTF_8),
    //                header.getBytes(StandardCharsets.UTF_8))) {
    //            throw new CsrfMismatchException("CSRF cookie/header mismatch");
    //        }
    //    }

}
