package org.tb.hiemdall.auth.utilities;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

class CookieCreatorTest {

    private CookieCreator creator;

    @BeforeEach
    void setUp() {
        creator = new CookieCreator();
    }

    @Test
    void shortLivedOauthCookieScopedToAuthPath() {
        ResponseCookie c = creator.shortLivedOauthCookie("csrf_state", "abc");

        assertThat(c.getName()).isEqualTo("csrf_state");
        assertThat(c.getValue()).isEqualTo("abc");
        assertThat(c.isHttpOnly()).isTrue();
        assertThat(c.getSameSite()).isEqualTo("Lax");
        assertThat(c.getPath()).isEqualTo("/auth/");
        assertThat(c.getMaxAge().getSeconds()).isEqualTo(600L);
    }

    @Test
    void clearedOauthCookieHasZeroMaxAge() {
        ResponseCookie c = creator.clearedOauthCookie("csrf_state");

        assertThat(c.getName()).isEqualTo("csrf_state");
        assertThat(c.getValue()).isEmpty();
        assertThat(c.getPath()).isEqualTo("/auth/");
        assertThat(c.getMaxAge().getSeconds()).isZero();
    }
}
