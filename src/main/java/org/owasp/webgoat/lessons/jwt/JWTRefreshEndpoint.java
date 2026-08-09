/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.http.ResponseEntity.ok;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.lang3.RandomStringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "jwt-refresh-hint1",
  "jwt-refresh-hint2",
  "jwt-refresh-hint3",
  "jwt-refresh-hint4"
})
public class JWTRefreshEndpoint implements AssignmentEndpoint {

  public static final String PASSWORD = "bm5nhSkxCXZkKRy4";

  /** HS512 needs a key of at least 512 bits; a short literal in the source does not qualify. */
  private static final int SIGNING_KEY_BYTES = 64;

  private static final Duration TOKEN_VALIDITY = Duration.ofMinutes(10);

  private static final String JWT_PASSWORD = generateSigningKey();

  /** Refresh token -> the user it was handed out to, so it can only refresh that user. */
  private static final Map<String, String> refreshTokenOwners = new ConcurrentHashMap<>();

  /**
   * Generated per JVM start, which invalidates outstanding tokens across a restart. Acceptable for
   * this single-instance training application; a clustered deployment would need a shared key.
   */
  private static String generateSigningKey() {
    byte[] key = new byte[SIGNING_KEY_BYTES];
    new SecureRandom().nextBytes(key);
    return TextCodec.BASE64.encode(key);
  }

  private static String stripBearerPrefix(String authorizationHeader) {
    return authorizationHeader.replace("Bearer ", "").trim();
  }

  @PostMapping(
      value = "/JWT/refresh/login",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public ResponseEntity follow(@RequestBody(required = false) Map<String, Object> json) {
    if (json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    String user = (String) json.get("user");
    String password = (String) json.get("password");

    if ("Jerry".equalsIgnoreCase(user) && PASSWORD.equals(password)) {
      return ok(createNewTokens(user));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
  }

  private Map<String, Object> createNewTokens(String user) {
    Instant issuedAt = Instant.now();
    Map<String, Object> claims = Map.of("admin", "false", "user", user);
    String token =
        Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(Date.from(issuedAt))
            .setExpiration(Date.from(issuedAt.plus(TOKEN_VALIDITY)))
            .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, JWT_PASSWORD)
            .compact();
    Map<String, Object> tokenJson = new HashMap<>();
    String refreshToken = RandomStringUtils.randomAlphabetic(20);
    refreshTokenOwners.put(refreshToken, user);
    tokenJson.put("access_token", token);
    tokenJson.put("refresh_token", refreshToken);
    return tokenJson;
  }

  @PostMapping("/JWT/refresh/checkout")
  @ResponseBody
  public ResponseEntity<AttackResult> checkout(
      @RequestHeader(value = "Authorization", required = false) String token) {
    if (token == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    try {
      Jws<Claims> jws =
          Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(stripBearerPrefix(token));
      String user = (String) jws.getBody().get("user");
      if ("Tom".equals(user)) {
        // Unreachable since parseClaimsJws rejects unsigned tokens; kept so the lesson's own
        // definition of success stays visible next to the check that now prevents it.
        if ("none".equals(jws.getHeader().getAlgorithm())) {
          return ok(success(this).feedback("jwt-refresh-alg-none").build());
        }
        return ok(success(this).build());
      }
      return ok(failed(this).feedback("jwt-refresh-not-tom").feedbackArgs(user).build());
    } catch (ExpiredJwtException e) {
      return ok(failed(this).output(e.getMessage()).build());
    } catch (JwtException | IllegalArgumentException e) {
      // An empty or blank bearer value makes jjwt raise IllegalArgumentException, not JwtException.
      return ok(failed(this).feedback("jwt-invalid-token").build());
    }
  }

  @PostMapping("/JWT/refresh/newToken")
  @ResponseBody
  public ResponseEntity newToken(
      @RequestHeader(value = "Authorization", required = false) String token,
      @RequestBody(required = false) Map<String, Object> json) {
    if (token == null || json == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    String refreshToken = (String) json.get("refresh_token");
    if (refreshToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    // The refresh token, not the presented access token, decides whose session is refreshed. The
    // access token may legitimately be expired here, and the claims of a token we accepted only
    // because it expired are not a trustworthy source of identity.
    String user = refreshTokenOwners.get(refreshToken);
    if (user == null || !presentsSignedTokenFor(token, user)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    // Conditional removal makes verifying and consuming the refresh token one atomic step.
    if (!refreshTokenOwners.remove(refreshToken, user)) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    return ok(createNewTokens(user));
  }

  /**
   * Accepts an expired access token - refreshing one is the point of this endpoint - but only if
   * it really carried a signature. jjwt reports expiry from inside {@code parse}, before {@code
   * parseClaimsJws} gets to reject unsigned tokens, so an {@code alg: none} token with an {@code
   * exp} in the past would otherwise reach us looking verified.
   */
  private boolean presentsSignedTokenFor(String authorizationHeader, String user) {
    try {
      Jws<Claims> jws =
          Jwts.parser()
              .setSigningKey(JWT_PASSWORD)
              .parseClaimsJws(stripBearerPrefix(authorizationHeader));
      return user.equals(jws.getBody().get("user"));
    } catch (ExpiredJwtException e) {
      return e.getHeader() instanceof JwsHeader && user.equals(e.getClaims().get("user"));
    } catch (JwtException | IllegalArgumentException e) {
      return false;
    }
  }
}
