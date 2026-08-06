package org.tb.hiemdall.auth.records;

public record HiemdallAuthResponseRecord(
        OAuthTokenResponse tokens,
        IdentityClaims identity,
        String csrfToken,
        String redirectPath) {}
