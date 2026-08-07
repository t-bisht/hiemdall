package org.tb.hiemdall.auth.gcp.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.tb.hiemdall.auth.exception.CsrfMismatchException;
import org.tb.hiemdall.auth.exception.LoginCancelledException;
import org.tb.hiemdall.auth.gcp.clients.GoogleTokenExchangeClient;
import org.tb.hiemdall.auth.identity.IdentityResolver;
import org.tb.hiemdall.auth.records.AuthCallBackRecord;
import org.tb.hiemdall.auth.records.HiemdallAuthResponseRecord;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;
import org.tb.hiemdall.auth.utilities.CookieCreator;
import org.tb.hiemdall.auth.utilities.OAuthStateGenerator;

@ExtendWith(MockitoExtension.class)
class GoogleAuthCallbackServiceTest {

    @Mock GoogleTokenExchangeClient tokenClient;
    @Mock IdentityResolver identityResolver;
    @Mock OAuthStateGenerator stateGenerator;
    @Mock CookieCreator cookieCreator;

    private GoogleAuthCallbackService service;

    @BeforeEach
    void setUp() {
        service = new GoogleAuthCallbackService();
        ReflectionTestUtils.setField(service, "googleClient", tokenClient);
        ReflectionTestUtils.setField(service, "identityResolver", identityResolver);
        ReflectionTestUtils.setField(service, "stateGenerator", stateGenerator);
        ReflectionTestUtils.setField(service, "cookieCreator", cookieCreator);
    }

    @Test
    void providerErrorShortCircuitsToLoginCancelled() {
        AuthCallBackRecord rec =
                new AuthCallBackRecord("access_denied", null, null, null, "/dashboard");

        assertThatThrownBy(() -> service.handleCallback(rec))
                .isInstanceOf(LoginCancelledException.class);

        verifyNoInteractions(tokenClient, identityResolver, stateGenerator, cookieCreator);
    }

    @Test
    void csrfMismatchPropagatesBeforeTokenExchange() {
        AuthCallBackRecord rec =
                new AuthCallBackRecord(null, "state-A", "state-B", "code", "/dash");

        assertThatThrownBy(() -> service.handleCallback(rec))
                .isInstanceOf(CsrfMismatchException.class);

        verifyNoInteractions(tokenClient, identityResolver);
    }

    @Test
    void successfulCallbackReturnsPopulatedResponse() {
        OAuthTokenResponse tokens =
                new OAuthTokenResponse("at", "rt", "idt", 3600L, "openid", "Bearer");
        IdentityClaims identity = new IdentityClaims("sub-1", "tb@example.com", "TB", "pic");

        when(tokenClient.exchangeCode("code-123")).thenReturn(tokens);
        when(identityResolver.resolve(tokens)).thenReturn(identity);
        when(stateGenerator.generate()).thenReturn("new-csrf");

        AuthCallBackRecord rec =
                new AuthCallBackRecord(null, "s", "s", "code-123", "/dashboard");
        HiemdallAuthResponseRecord result = service.handleCallback(rec);

        assertThat(result.tokens()).isSameAs(tokens);
        assertThat(result.identity()).isSameAs(identity);
        assertThat(result.csrfToken()).isEqualTo("new-csrf");
        assertThat(result.redirectPath()).isEqualTo("/dashboard");
    }
}
