package org.tb.hiemdall.auth.handoff;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.tb.hiemdall.auth.records.IdentityClaims;
import org.tb.hiemdall.auth.records.OAuthTokenResponse;

class HandoffStoreTest {

    private static final OAuthTokenResponse TOKENS =
            new OAuthTokenResponse("at", "rt", "idt", 3600L, "openid", "Bearer");
    private static final IdentityClaims ID = new IdentityClaims("sub", "u@e.com", "U", null);

    private MutableClock clock;
    private HandoffStore store;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(Instant.parse("2026-10-04T10:00:00Z"));
        store =
                new HandoffStore(
                        new HandoffProperties(Duration.ofSeconds(60), 3, Duration.ofSeconds(10)),
                        clock);
    }

    @Test
    void putReturnsOpaqueCodeAndConsumeReturnsSameBundle() {
        String code = store.put("stash", TOKENS, ID);

        assertThat(code).isNotBlank().doesNotContain("+", "/", "=");

        HandoffEntry got = store.consume("stash", code);
        assertThat(got).isNotNull();
        assertThat(got.tokens()).isSameAs(TOKENS);
        assertThat(got.identity()).isSameAs(ID);
        assertThat(got.appId()).isEqualTo("stash");
    }

    @Test
    void consumeIsOneShot_replayReturnsNull() {
        String code = store.put("stash", TOKENS, ID);
        assertThat(store.consume("stash", code)).isNotNull();
        assertThat(store.consume("stash", code)).isNull();
    }

    @Test
    void expiredEntryReturnsNull() {
        String code = store.put("stash", TOKENS, ID);
        clock.advance(Duration.ofSeconds(61));
        assertThat(store.consume("stash", code)).isNull();
    }

    @Test
    void wrongAppReturnsNullAndDoesNotLeaveEntryForRealOwner() {
        String code = store.put("stash", TOKENS, ID);
        assertThat(store.consume("other", code)).isNull();
        // The mismatched consume removed the entry — a subsequent legit consume also sees nothing.
        // This is the intended behaviour (fail-closed) rather than resurrection.
        assertThat(store.consume("stash", code)).isNull();
    }

    @Test
    void unknownCodeReturnsNull() {
        assertThat(store.consume("stash", "no-such-code")).isNull();
    }

    @Test
    void blankInputsReturnNull() {
        assertThat(store.consume("stash", "")).isNull();
        assertThat(store.consume("stash", null)).isNull();
        assertThat(store.consume(null, "x")).isNull();
    }

    @Test
    void maxEntriesCapRejectsWhenFull() {
        store.put("a", TOKENS, ID);
        store.put("b", TOKENS, ID);
        store.put("c", TOKENS, ID);

        assertThatThrownBy(() -> store.put("d", TOKENS, ID))
                .isInstanceOf(HandoffStoreFullException.class);
    }

    @Test
    void capacitySweepReclaimsExpiredSlots() {
        store.put("a", TOKENS, ID);
        store.put("b", TOKENS, ID);
        store.put("c", TOKENS, ID);
        clock.advance(Duration.ofSeconds(61));
        // At capacity but all 3 are expired — put should sweep and succeed.
        String fresh = store.put("d", TOKENS, ID);
        assertThat(store.consume("d", fresh)).isNotNull();
    }

    @Test
    void sweepDropsExpiredAndKeepsLive() {
        store.put("old", TOKENS, ID);
        clock.advance(Duration.ofSeconds(61));
        String live = store.put("new", TOKENS, ID);

        int dropped = store.sweep();
        assertThat(dropped).isEqualTo(1);
        assertThat(store.consume("new", live)).isNotNull();
    }

    /** Clock whose {@link #instant()} is advanced by test code — avoids real sleep. */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
