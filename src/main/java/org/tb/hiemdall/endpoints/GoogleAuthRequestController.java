package org.tb.hiemdall.endpoints;

import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.POST_LOGIN_COOKIE;
import static org.tb.hiemdall.auth.gcp.GCPAuthConstants.STATE_COOKIE;

import jakarta.annotation.Resource;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.tb.hiemdall.auth.records.AuthCallBackRecord;
import org.tb.hiemdall.services.GoogleAuthServices;

@RestController
@RequestMapping("/auth/google")
public class GoogleAuthRequestController {

    @Resource GoogleAuthServices gauthService;

    @GetMapping("/start")
    public ResponseEntity<Map<String, String>> startGoogleLogin(
            @RequestParam(name = "app", required = true) String appID) {

        return gauthService.startGoogleAuthService(appID);
    }

    @GetMapping("/callback")
    public ResponseEntity<Void> handleGoogleCallback(
            @RequestParam(name = "code", required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            @CookieValue(name = STATE_COOKIE, required = false) String stateCookie,
            @CookieValue(name = POST_LOGIN_COOKIE, required = false) String postLoginCookie) {
        return gauthService.handleAuthCallback(
                new AuthCallBackRecord(error, state, stateCookie, code, postLoginCookie));
    }
}
