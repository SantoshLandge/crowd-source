package com.crowdsource.userservice.controller;

import com.crowdsource.userservice.util.JwtUtil;
import com.crowdsource.userservice.util.PemKeyLoader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.ECPublicKey;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Publishes the public signing key. Consumed by the api-gateway to validate access tokens. */
@Slf4j
@RestController
public class JwksController {

    private final PemKeyLoader pemKeyLoader;

    public JwksController(PemKeyLoader pemKeyLoader) {
        this.pemKeyLoader = pemKeyLoader;
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        ECPublicKey publicKey = (ECPublicKey) pemKeyLoader.getPublicKey();

        ECKey jwk = new ECKey.Builder(Curve.P_256, publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .keyID(JwtUtil.KEY_ID)          // same kid that JwtUtil puts into every token
                .build();

        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(5, TimeUnit.MINUTES).cachePublic())
                .body(new JWKSet(jwk).toJSONObject());
    }
}
