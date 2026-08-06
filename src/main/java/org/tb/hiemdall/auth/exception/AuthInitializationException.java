package org.tb.hiemdall.auth.exception;

/** Raised when OAuth flow initialization fails before redirecting the user to Google. */
public class AuthInitializationException extends AuthFlowException {

    private static final long serialVersionUID = 1L;

    private static final String ERROR_CODE = "auth_init_failed";

    public AuthInitializationException(String message) {
        super(message);
    }

    public AuthInitializationException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public String errorCode() {
        return ERROR_CODE;
    }
}
