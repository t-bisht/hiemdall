package org.tb.hiemdall.auth.records;

public record AuthCallBackRecord(
        String error, String state, String stateCookie, String code, String postLoginCookie) {}
