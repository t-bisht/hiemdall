package org.tb.hiemdall.auth.gcp;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.tb.hiemdall.auth.gcp.services.GoogleAuthCallbackService;
import org.tb.hiemdall.auth.gcp.services.GoogleAuthStartService;


@Service
public class GCPLoginOrchestrator {
    @Autowired
    GoogleAuthCallbackService authCallBackService;
    @Autowired
    GoogleAuthStartService authStartService;


    public ResponseEntity<Void> initGoogleAuth(String redirect, String appCode) {

    }

}
