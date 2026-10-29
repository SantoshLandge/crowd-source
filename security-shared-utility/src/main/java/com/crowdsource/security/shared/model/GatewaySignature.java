package com.crowdsource.security.shared.model;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * HMAC-SHA256 signature over the identity headers forwarded by the gateway.
 * <p>
 * NOTE: the gateway module (reactive, no dependency on this library) contains an identical
 * implementation. If you change the canonical format here, change it there as well.
 */
public final class GatewaySignature {

    private static final String ALGORITHM = "HmacSHA256";

    private GatewaySignature() {
    }

    public static String sign(String secret, String userId, String username, String authorities, long timestampMillis) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM));
            byte[] digest = mac.doFinal(canonical(userId, username, authorities, timestampMillis)
                    .getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to compute gateway signature", e);
        }
    }

    /** Constant-time comparison. */
    public static boolean matches(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }

    static String canonical(String userId, String username, String authorities, long timestampMillis) {
        return nullToEmpty(userId) + "\n" + nullToEmpty(username) + "\n"
                + nullToEmpty(authorities) + "\n" + timestampMillis;
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
