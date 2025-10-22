package com.deliverytech.delivery.security;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

/**
 * Componente utilitário encapsulando a lógica de análise e validação de JWT.
 */
@Component
public class JwtUtil {

    private final SecretKey signingKey;

    public JwtUtil(@Value("${security.jwt.secret}") String secret) {
        Objects.requireNonNull(secret, "security.jwt.secret must be configured");
        var keyBytes = Decoders.BASE64.decode(secret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public Optional<String> extractSubject(String token) {
        return parseClaims(token).map(Claims::getSubject);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        return isTokenValid(token, userDetails.getUsername());
    }

    public boolean isTokenValid(String token, String expectedSubject) {
        return parseClaims(token)
                .filter(claims -> {
                    var subject = claims.getSubject();
                    return subject != null && subject.equals(expectedSubject);
                })
                .filter(claims -> !isExpired(claims))
                .isPresent();
    }

    private boolean isExpired(Claims claims) {
        Date expiration = claims.getExpiration();
        return expiration != null && expiration.toInstant().isBefore(Instant.now());
    }

    private Optional<Claims> parseClaims(String token) {
        try {
            return Optional.of(
                    Jwts.parser()
                            .verifyWith(signingKey)
                            .build()
                            .parseSignedClaims(token)
                            .getPayload()
            );
        } catch (JwtException | IllegalArgumentException ex) {
            return Optional.empty();
        }
    }
}
