package org.tb.hiemdall.endpoints;

import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth/google")
public class GoogleAuthRequestHandler {

    @Resource
    @Qualifier("appRegister")
    Map<String, String> appRegister;

    @GetMapping("/google/start")
    public ResponseEntity<Void> startGoogleLogin(
            @RequestParam(name = "redirect", required = false) String redirect,
            @RequestParam(name = "app", required = false) String appID) {

        if (appRegister.containsKey(appID)) {
            //start further process

        }
        // return response that map is not registered and appropriate status

        return null;

    }
}