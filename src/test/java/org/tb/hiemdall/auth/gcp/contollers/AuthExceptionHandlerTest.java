package org.tb.hiemdall.auth.gcp.contollers;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.tb.hiemdall.auth.exception.CsrfMismatchException;
import org.tb.hiemdall.auth.exception.EmailUnverifiedException;
import org.tb.hiemdall.auth.exception.GoogleTokenExchangeFailedException;
import org.tb.hiemdall.auth.exception.IdTokenMalformedException;
import org.tb.hiemdall.auth.exception.LoginCancelledException;

class AuthExceptionHandlerTest {

    private final AuthExceptionHandler handler = new AuthExceptionHandler();

    @Test
    void userCancelRedirectsWithAccessDenied() {
        ResponseEntity<Void> resp = handler.onCancelled(new LoginCancelledException("access_denied"));
        assertRedirect(resp, "access_denied");
    }

    @Test
    void providerErrorRedirectsWithProviderCode() {
        ResponseEntity<Void> resp = handler.onCancelled(new LoginCancelledException("server_error"));
        assertRedirect(resp, "server_error");
    }

    @Test
    void csrfMismatchRedirectsWithStateInvalid() {
        ResponseEntity<Void> resp =
                handler.onUserOrCsrfIssue(new CsrfMismatchException("boom"));
        assertRedirect(resp, "state_invalid");
    }

    @Test
    void emailUnverifiedRedirectsWithEmailUnverified() {
        ResponseEntity<Void> resp =
                handler.onUserOrCsrfIssue(new EmailUnverifiedException("boom"));
        assertRedirect(resp, "email_unverified");
    }

    @Test
    void tokenExchangeFailureRedirectsWithCodeExchangeFailed() {
        ResponseEntity<Void> resp =
                handler.onUpstreamFailure(new GoogleTokenExchangeFailedException("boom"));
        assertRedirect(resp, "code_exchange_failed");
    }

    @Test
    void idTokenMalformedRedirectsWithCodeExchangeFailed() {
        ResponseEntity<Void> resp =
                handler.onUpstreamFailure(new IdTokenMalformedException("boom"));
        assertRedirect(resp, "code_exchange_failed");
    }

    private static void assertRedirect(ResponseEntity<Void> resp, String errCode) {
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(resp.getHeaders().getLocation()).isNotNull();
        assertThat(resp.getHeaders().getLocation().toString())
                .isEqualTo("/login?err=" + errCode);
    }
}
