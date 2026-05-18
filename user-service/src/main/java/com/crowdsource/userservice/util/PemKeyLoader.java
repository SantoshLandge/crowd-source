package com.crowdsource.userservice.util;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

@Slf4j
@Component
public class PemKeyLoader {

    @Value("${jwt.private-key.path:keys/private.pem}")
    private String privateKeyPath;

    @Value("${jwt.public-key.path:keys/public.pem}")
    private String publicKeyPath;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    public void init() {
        try {
            this.privateKey = loadPrivateKey(privateKeyPath);
            this.publicKey = loadPublicKey(publicKeyPath);
            log.info("Successfully loaded ECDSA keys from PEM files");
        } catch (Exception e) {
            log.error("Failed to load JWT signing keys", e);
            throw new RuntimeException("JWT initialization failed", e);
        }
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    private PrivateKey loadPrivateKey(String resourcePath) throws Exception {
        ClassPathResource resource = new ClassPathResource(resourcePath);
        String pemContent = new BufferedReader(new InputStreamReader(resource.getInputStream()))
                .lines()
                .collect(Collectors.joining("\n"));

        // Remove PEM headers/footers
        String privateKeyPem = pemContent
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(privateKeyPem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKey(String resourcePath) throws Exception {
        ClassPathResource resource = new ClassPathResource(resourcePath);
        String pemContent = new BufferedReader(new InputStreamReader(resource.getInputStream()))
                .lines()
                .collect(Collectors.joining("\n"));

        // Remove PEM headers/footers
        String publicKeyPem = pemContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }
}