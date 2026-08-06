package org.tb.hiemdall.auth.utilities;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.tb.hiemdall.auth.exception.CsrfMismatchException;

public class CSRFStateMatchUtility {
    /**
     * CSRF check for the OAuth callback — state param must match state cookie. Constant-time
     * compare to avoid timing-based state exfiltration.
     */
    public static Boolean verifyCsrfState(String stateParam, String stateCookie) {
        if (stateParam == null || stateParam.isBlank()) {
            throw new CsrfMismatchException("state query param missing");
        }
        if (stateCookie == null || stateCookie.isBlank()) {
            throw new CsrfMismatchException("CSRF auth cookie missing");
        }
        if (!MessageDigest.isEqual(
                stateParam.getBytes(StandardCharsets.UTF_8),
                stateCookie.getBytes(StandardCharsets.UTF_8))) {
            throw new CsrfMismatchException("CSRF auth mismatch");
        }
        return true;
    }
}
