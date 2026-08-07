package org.tb.hiemdall.auth.utilities;

import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.*;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieCreator {

    public ResponseCookie shortLivedOauthCookie(String name, String value) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .sameSite("Lax")
                .path(OAUTH_COOKIE_PATH)
                .maxAge(OAUTH_COOKIE_TTL_SECONDS)
                .build();
    }

    /** Zero-max-age cookie that instructs the browser to delete the named oauth cookie. */
    public ResponseCookie clearedOauthCookie(String name) {
        return ResponseCookie.from(name, "").path(OAUTH_COOKIE_PATH).maxAge(0).build();
    }
}
