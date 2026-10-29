package com.crowdsource.security.shared.model;

import java.util.List;

/**
 * Header contract between the API gateway and every downstream service.
 * <p>
 * The gateway validates the JWT, then forwards the identity in these headers and signs them with
 * an HMAC (see {@link GatewaySignature}). Downstream services only trust the identity if the
 * signature verifies, so a caller that reaches a service directly cannot impersonate a user.
 */
public final class GatewayHeaders {

    public static final String USER_ID = "X-User-Id";
    public static final String USER_NAME = "X-User-Name";
    public static final String AUTHORITIES = "X-User-Authorities";
    public static final String TIMESTAMP = "X-Gateway-Timestamp";
    public static final String SIGNATURE = "X-Gateway-Signature";

    /** All headers that make up the forwarded identity (used for stripping and propagation). */
    public static final List<String> ALL = List.of(USER_ID, USER_NAME, AUTHORITIES, TIMESTAMP, SIGNATURE);

    private GatewayHeaders() {
    }
}
