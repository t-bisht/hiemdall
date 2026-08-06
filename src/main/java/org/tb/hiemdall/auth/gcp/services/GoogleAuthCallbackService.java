package org.tb.hiemdall.auth.gcp.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.tb.hiemdall.auth.exception.LoginCancelledException;
import org.tb.hiemdall.auth.gcp.clients.GoogleTokenExchangeClient;
import org.tb.hiemdall.auth.identity.IdentityResolver;
import org.tb.hiemdall.auth.records.AuthCallBackRecord;
import org.tb.hiemdall.auth.records.HiemdallAuthResponseRecord;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;
import org.tb.hiemdall.auth.utilities.CSRFStateMatchUtility;
import org.tb.hiemdall.auth.utilities.CookieCreator;
import org.tb.hiemdall.auth.utilities.OAuthStateGenerator;

@Service
public class GoogleAuthCallbackService {

    private static final Logger log = LoggerFactory.getLogger(GoogleAuthCallbackService.class);

    @Autowired GoogleTokenExchangeClient googleClient;

    @Autowired
    @Qualifier("googleOIDC")
    IdentityResolver identityResolver;

    @Autowired OAuthStateGenerator stateGenerator;

    @Autowired CookieCreator cookieCreator;

    public HiemdallAuthResponseRecord handleCallback(AuthCallBackRecord callbackRecord) {

        String error = callbackRecord.error();
        String state = callbackRecord.state();
        String stateCookie = callbackRecord.stateCookie();
        String code = callbackRecord.code();
        String postLoginCookie = callbackRecord.postLoginCookie();

        // rely on error to fail fast
        if (error != null && !error.isBlank()) {
            throw new LoginCancelledException(error);
        }

        // match CSRF stateCookie comes from browser and state comes from google
        CSRFStateMatchUtility.verifyCsrfState(state, stateCookie);

        // Process: OAuth 2.0 Authorization Code Exchange (RFC 6749 §4.1.3). Also called
        // "code-for-token exchange" or "token exchange step".
        // Google generated code would be used to generate the OATUH token
        OAuthTokenResponse tokens = googleClient.exchangeCode(code);

        // resolve provider tokens → provider-neutral identity (OIDC decodes id_token, non-OIDC hits
        // userinfo)
        IdentityClaims identity = identityResolver.resolve(tokens);

        String csrfToken = stateGenerator.generate();

        return new HiemdallAuthResponseRecord(tokens, identity, csrfToken, postLoginCookie);
    }
}
