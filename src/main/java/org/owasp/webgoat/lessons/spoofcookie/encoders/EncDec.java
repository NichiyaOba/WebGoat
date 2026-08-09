/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.crypto.codec.Hex;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  /**
   * The cookie used to be lowercase + salt, reversed, hex, Base64 - every step reversible without
   * a secret, so anyone could decode their own cookie, put another user's name in it and encode it
   * back. Encoding is not authentication. The value now carries an HMAC over itself, keyed by a
   * secret that never leaves the server, so a modified value no longer verifies.
   */
  private static final String HMAC_ALGORITHM = "HmacSHA256";

  private static final int SIGNING_KEY_BYTES = 32;

  private static final SecretKeySpec SIGNING_KEY = generateSigningKey();

  private EncDec() {}

  private static SecretKeySpec generateSigningKey() {
    byte[] key = new byte[SIGNING_KEY_BYTES];
    new SecureRandom().nextBytes(key);
    return new SecretKeySpec(key, HMAC_ALGORITHM);
  }

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String payload = value.toLowerCase();
    return base64Encode(payload + "|" + sign(payload));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String decoded = base64Decode(encodedValue);
    int separator = decoded.lastIndexOf('|');
    if (separator < 0) {
      throw new IllegalArgumentException("Cookie is not signed");
    }

    String payload = decoded.substring(0, separator);
    String signature = decoded.substring(separator + 1);
    if (!MessageDigest.isEqual(
        sign(payload).getBytes(StandardCharsets.UTF_8),
        signature.getBytes(StandardCharsets.UTF_8))) {
      throw new IllegalArgumentException("Cookie signature does not match");
    }
    return payload;
  }

  private static String sign(final String value) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(SIGNING_KEY);
      return new String(Hex.encode(mac.doFinal(value.getBytes(StandardCharsets.UTF_8))));
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new IllegalStateException("Unable to sign cookie", e);
    }
  }

  private static String base64Encode(final String value) {
    return Base64.getEncoder().encodeToString(value.getBytes());
  }

  private static String base64Decode(final String value) {
    byte[] decoded = Base64.getDecoder().decode(value.getBytes());
    return new String(decoded);
  }
}
