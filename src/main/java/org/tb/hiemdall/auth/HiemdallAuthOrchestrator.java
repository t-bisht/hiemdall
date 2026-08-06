package org.tb.hiemdall.auth;

import org.tb.hiemdall.auth.records.AuthCallBackRecord;
import org.tb.hiemdall.auth.records.HiemdallAuthResponseRecord;
import org.tb.hiemdall.auth.records.InitAuthRecord;

public interface HiemdallAuthOrchestrator {
    InitAuthRecord initiateAuthProcess(String appID);

    HiemdallAuthResponseRecord handleAuthCallBack(AuthCallBackRecord callbackObj);
}
