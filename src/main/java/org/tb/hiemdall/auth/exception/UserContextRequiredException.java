package org.tb.hiemdall.auth.exception;

/** Authorization: Bearer &lt;jwt&gt; missing on a user-scoped /internal/** call. */
public class UserContextRequiredException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public UserContextRequiredException(String message) {
        super(message);
    }
}
