package com.crowdsource.userservice.util;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Loads the ES256 (EC P-256) signing key pair.
 * <p>
 * Locations accept any Spring resource prefix, e.g. {@code classpath:keys/private.pem} (local dev) or
 * {@code file:/run/secrets/jwt-private.pem} (containers / production). Without a prefix, classpath is assumed.
 * <p>
 * Generate a pair:
 * <pre>
 *   openssl ecparam -name prime256v1 -genkey -noout -out ec.pem
 *   openssl pkcs8 -topk8 -nocrypt -in ec.pem -out private.pem
 *   openssl ec -in ec.pem -pubout -out public.pem
 * </pre>
 */
@Slf4j
@Component
public class PemKeyLoader {

    private final ResourceLoader resourceLoader;

    @Value("${jwt.private-key.path:classpath:keys/private.pem}")
    private String privateKeyPath;

    @Value("${jwt.public-key.path:classpath:keys/public.pem}")
    private String publicKeyPath;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public PemKeyLoader(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void init() {
        try {
            this.privateKey = loadPrivateKey(privateKeyPath);
            this.publicKey = loadPublicKey(publicKeyPath);
            requireP256();
            log.info("Loaded ES256 signing keys (private: {}, public: {})", privateKeyPath, publicKeyPath);
        } catch (Exception e) {
            log.error("Failed to load JWT signing keys", e);
            throw new IllegalStateException("JWT key initialization failed: " + e.getMessage(), e);
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private void requireP256() {
        if (!(privateKey instanceof ECPrivateKey ecPrivate) || !(publicKey instanceof ECPublicKey ecPublic)
                || ecPrivate.getParams().getCurve().getField().getFieldSize() != 256
                || ecPublic.getParams().getCurve().getField().getFieldSize() != 256) {
            throw new IllegalStateException("JWT keys must be EC P-256 (prime256v1) keys to be used with ES256");
        }
    }

    private PrivateKey loadPrivateKey(String location) throws Exception {
        String pem = read(location);
        if (pem.contains("BEGIN EC PRIVATE KEY")) {
            throw new IllegalStateException("Private key is in SEC1 format; convert it with: "
                    + "openssl pkcs8 -topk8 -nocrypt -in ec.pem -out private.pem");
        }
        byte[] der = Base64.getDecoder().decode(stripPem(pem));
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private PublicKey loadPublicKey(String location) throws Exception {
        byte[] der = Base64.getDecoder().decode(stripPem(read(location)));
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
    }

    private String read(String location) throws Exception {
        String resolved = location.matches("^[a-zA-Z][a-zA-Z0-9+.-]*:.*") ? location : "classpath:" + location;
        Resource resource = resourceLoader.getResource(resolved);
        try (InputStream in = resource.getInputStream()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String stripPem(String pem) {
        return pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
    }
}
