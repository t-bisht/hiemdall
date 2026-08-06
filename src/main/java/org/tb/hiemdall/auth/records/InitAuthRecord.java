package org.tb.hiemdall.auth.records;

public record InitAuthRecord(String csrfToken, String authRedirectURL, String postRedirectURL) {}
