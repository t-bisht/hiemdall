package org.tb.hiemdall.auth.handoff;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Config for the browser → app-backend handoff cache. Bound to {@code app.handoff.*}.
 *
 * <ul>
 *   <li>{@code ttl} — how long an entry stays redeemable after {@code put}. Should comfortably
 *       cover the browser-redirect + SPA → backend round-trip (seconds, not minutes).
 *   <li>{@code maxEntries} — hard cap so a stuck/misbehaving app can't blow up heap.
 *   <li>{@code sweepEvery} — cadence of the background sweeper that drops expired entries.
 * </ul>
 */
@Validated
@ConfigurationProperties(prefix = "app.handoff")
public record HandoffProperties(
        @NotNull Duration ttl, @Min(1) int maxEntries, @NotNull Duration sweepEvery) {}
