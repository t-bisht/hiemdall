package org.tb.hiemdall.auth.utilities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.tb.hiemdall.auth.exception.CsrfMismatchException;

class CSRFStateMatchUtilityTest {

    @Test
    void returnsTrueOnExactMatch() {
        assertThat(CSRFStateMatchUtility.verifyCsrfState("abc-123", "abc-123")).isTrue();
    }

    @Test
    void throwsOnMismatch() {
        assertThatThrownBy(() -> CSRFStateMatchUtility.verifyCsrfState("abc", "xyz"))
                .isInstanceOf(CsrfMismatchException.class)
                .hasMessageContaining("mismatch");
    }

    @Test
    void throwsOnDifferentLength() {
        assertThatThrownBy(() -> CSRFStateMatchUtility.verifyCsrfState("abc", "abcd"))
                .isInstanceOf(CsrfMismatchException.class);
    }

    @Test
    void throwsWhenStateParamNull() {
        assertThatThrownBy(() -> CSRFStateMatchUtility.verifyCsrfState(null, "abc"))
                .isInstanceOf(CsrfMismatchException.class)
                .hasMessageContaining("state query param missing");
    }

    @Test
    void throwsWhenStateParamBlank() {
        assertThatThrownBy(() -> CSRFStateMatchUtility.verifyCsrfState("   ", "abc"))
                .isInstanceOf(CsrfMismatchException.class)
                .hasMessageContaining("state query param missing");
    }

    @Test
    void throwsWhenCookieNull() {
        assertThatThrownBy(() -> CSRFStateMatchUtility.verifyCsrfState("abc", null))
                .isInstanceOf(CsrfMismatchException.class)
                .hasMessageContaining("cookie missing");
    }

    @Test
    void throwsWhenCookieBlank() {
        assertThatThrownBy(() -> CSRFStateMatchUtility.verifyCsrfState("abc", ""))
                .isInstanceOf(CsrfMismatchException.class)
                .hasMessageContaining("cookie missing");
    }
}
