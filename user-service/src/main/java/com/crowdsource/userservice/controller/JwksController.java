package com.crowdsource.userservice.controller;

import com.crowdsource.userservice.util.PemKeyLoader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.ECPublicKey;
import java.util.Map;

@Slf4j
@RestController
public class JwksController {

    private final PemKeyLoader pemKeyLoader;

    public JwksController(PemKeyLoader pemKeyLoader) {
        this.pemKeyLoader = pemKeyLoader;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        log.info("GET: /.well-known/jwks.json");
        // 1. Cast the loaded PublicKey to ECPublicKey
        ECPublicKey publicKey = (ECPublicKey) pemKeyLoader.getPublicKey();

        // 2. Build the Nimbus ECKey object
        // The 'kid' (Key ID) is important for rotation; for now, we use a static one
        ECKey jwk = new ECKey.Builder(Curve.P_256, publicKey)
                .keyID("auth-key-1")
                .build();

        // 3. Return the JWKSet as a Map (which Spring serializes to JSON)
        return new JWKSet(jwk).toJSONObject();
    }
}
