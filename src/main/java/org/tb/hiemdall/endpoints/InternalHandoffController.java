package org.tb.hiemdall.endpoints;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.tb.hiemdall.auth.handoff.ExchangeResponse;
import org.tb.hiemdall.auth.handoff.HandoffEntry;
import org.tb.hiemdall.auth.handoff.HandoffExchangeRequest;
import org.tb.hiemdall.auth.handoff.HandoffStore;

/**
 * Back-channel endpoint apps use to redeem a browser-side handoff code for the actual Google token
 * bundle. Lives under {@code /internal/**} so it's guarded by {@link
 * org.tb.hiemdall.security.security.InternalAuthFilter} — only callers with the shared {@code
 * X-Internal-Auth} secret can hit it.
 *
 * <p>Collapses every miss (unknown / expired / wrong-app) to a single 404 so a probing caller can't
 * tell them apart.
 */
@RestController
@RequestMapping("/internal/auth")
public class InternalHandoffController {

    private static final Logger log = LoggerFactory.getLogger(InternalHandoffController.class);

    @Autowired HandoffStore handoffStore;

    @PostMapping("/exchange")
    public ResponseEntity<ExchangeResponse> exchange(@RequestBody HandoffExchangeRequest body) {
        if (body == null
                || body.app() == null
                || body.app().isBlank()
                || body.handoff() == null
                || body.handoff().isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        HandoffEntry entry = handoffStore.consume(body.app(), body.handoff());
        if (entry == null) {
            log.info("handoff exchange miss for app '{}'", body.app());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        return ResponseEntity.ok(new ExchangeResponse(entry.tokens(), entry.identity()));
    }
}
