package org.tb.hiemdall.endpoints;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tb.hiemdall.auth.refresh.TokenRefreshRequest;
import org.tb.hiemdall.services.GoogleTokenRefreshService;

/**
 * Back-channel endpoint registered apps use to swap a Google refresh_token for a fresh
 * access_token. Lives under {@code /internal/**} so {@link
 * org.tb.hiemdall.security.security.InternalAuthFilter} guards it. Hiemdall stores nothing; the
 * calling app owns refresh-token storage.
 */
@RestController
@RequestMapping("/internal/auth/google")
public class GoogleTokenRefreshController {

    @Autowired GoogleTokenRefreshService refreshService;

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody TokenRefreshRequest body) {
        return refreshService.refresh(body);
    }
}
