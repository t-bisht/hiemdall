package org.tb.hiemdall.security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.tb.hiemdall.security.config.InternalAuthProperties;

/**
 * Filter for the {@code /internal/**} boundary. Requires {@code X-Internal-Auth} header to equal
 * the shared secret in {@link InternalAuthProperties#svcToken()} (constant-time compare). Writes
 * 401 directly on failure — these requests are service-to-service and never want the default HTML
 * error page.
 */
@Component
public class InternalAuthFilter extends OncePerRequestFilter {

    public static final String INTERNAL_AUTH_HEADER = "X-Internal-Auth";

    private final InternalAuthProperties props;

    public InternalAuthFilter(InternalAuthProperties props) {
        this.props = props;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String svcHeader = request.getHeader(INTERNAL_AUTH_HEADER);
        if (svcHeader == null || svcHeader.isBlank()) {
            writeUnauthorized(response, "X-Internal-Auth header missing");
            return;
        }
        if (!MessageDigest.isEqual(
                svcHeader.getBytes(StandardCharsets.UTF_8),
                props.svcToken().getBytes(StandardCharsets.UTF_8))) {
            writeUnauthorized(response, "X-Internal-Auth does not match");
            return;
        }

        chain.doFilter(request, response);
    }

    private static void writeUnauthorized(HttpServletResponse response, String reason)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + reason + "\"}");
    }
}
