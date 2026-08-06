package org.tb.hiemdall.auth.gcp;

import jakarta.annotation.Resource;
import org.springframework.stereotype.Service;
import org.tb.hiemdall.auth.HiemdallAuthOrchestrator;
import org.tb.hiemdall.auth.gcp.services.GoogleAuthCallbackService;
import org.tb.hiemdall.auth.gcp.services.GoogleAuthStartService;
import org.tb.hiemdall.auth.records.AuthCallBackRecord;
import org.tb.hiemdall.auth.records.HiemdallAuthResponseRecord;
import org.tb.hiemdall.auth.records.InitAuthRecord;

@Service("gcpauthorca")
public class GCPLoginOrchestrator implements HiemdallAuthOrchestrator {

    @Resource GoogleAuthStartService googleAuthStartService;

    @Resource GoogleAuthCallbackService authCallBackService;

    @Override
    public InitAuthRecord initiateAuthProcess(String appID) {
        return googleAuthStartService.createAuthInitializationRecord(appID);
    }

    @Override
    public HiemdallAuthResponseRecord handleAuthCallBack(AuthCallBackRecord callbackObj) {
        return authCallBackService.handleCallback(callbackObj);
    }
}
