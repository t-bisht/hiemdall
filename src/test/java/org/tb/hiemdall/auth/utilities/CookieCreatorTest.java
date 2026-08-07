package org.tb.hiemdall.auth.utilities;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;
import org.springframework.test.util.ReflectionTestUtils;
import org.tb.hiemdall.security.config.JwtProperties;

class CookieCreatorTest {

    private static final long EXPIRATION_HOURS = 24L;

    private CookieCreator creator;

    @BeforeEach
    void setUp() {
        creator = new CookieCreator();
        JwtProperties props = new JwtProperties("/tmp/key.pem", "kid-1", "hiemdall", EXPIRATION_HOURS);
        ReflectionTestUtils.setField(creator, "jwtProps", props);
    }

    @Test
    void sessionCookieCarriesJwtWithSessionFlags() {
        ResponseCookie c = creator.sessionCookie("jwt-value");

        assertThat(c.getName()).isEqualTo("kk_session");
        assertThat(c.getValue()).isEqualTo("jwt-value");
        assertThat(c.isHttpOnly()).isTrue();
        assertThat(c.getSameSite()).isEqualTo("Lax");
        assertThat(c.getPath()).isEqualTo("/");
        assertThat(c.getMaxAge().getSeconds()).isEqualTo(EXPIRATION_HOURS * 3600L);
    }

    @Test
    void csrfCookieIsReadableByJs() {
        ResponseCookie c = creator.csrfCookie("csrf-token");

        assertThat(c.getName()).isEqualTo("kk_csrf");
        assertThat(c.getValue()).isEqualTo("csrf-token");
        assertThat(c.isHttpOnly()).isFalse();
        assertThat(c.getSameSite()).isEqualTo("Lax");
        assertThat(c.getPath()).isEqualTo("/");
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
