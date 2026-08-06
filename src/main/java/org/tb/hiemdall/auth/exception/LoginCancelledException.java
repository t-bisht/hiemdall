package org.tb.hiemdall.auth.exception;

/**
 * Google returned an {@code error} param on the /callback redirect. Covers user cancel ({@code
 * access_denied}) and provider-side failures ({@code invalid_request}, {@code server_error}, {@code
 * admin_policy_enforced}, etc). Spec §4.3 first branch.
 */
public class LoginCancelledException extends AuthFlowException {

    private static final long serialVersionUID = 1L;

    private final String providerError;

    public LoginCancelledException(String providerError) {
        super("OAuth error: " + providerError);
        this.providerError = providerError;
    }

    @Override
    public String errorCode() {
        return providerError;
    }
}
