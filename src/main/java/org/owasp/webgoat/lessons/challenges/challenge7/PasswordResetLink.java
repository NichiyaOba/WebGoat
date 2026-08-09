/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.security.SecureRandom;
import java.util.Random;

/**
 * WARNING: DO NOT CHANGE FILE WITHOUT CHANGING .git contents
 *
 * @author nbaars
 * @since 8/17/17.
 */
public class PasswordResetLink {

  public String createPasswordReset(String username, String key) {
    // admin used to get random.setSeed(key.length()), which made its reset link the same value on
    // every run and derivable by anyone who could read this code. A reset link is a bearer
    // credential: it has to be unpredictable for every account, with no exceptions.
    SecureRandom random = new SecureRandom();
    return scramble(random, scramble(random, scramble(random, MD5.getHashString(username))));
  }

  public static String scramble(Random random, String inputString) {
    char[] a = inputString.toCharArray();
    for (int i = 0; i < a.length; i++) {
      int j = random.nextInt(a.length);
      char temp = a[i];
      a[i] = a[j];
      a[j] = temp;
    }
    return new String(a);
  }

  public static void main(String[] args) {
    if (args == null || args.length != 2) {
      System.out.println("Need a username and key");
      System.exit(1);
    }
    String username = args[0];
    String key = args[1];
    System.out.println("Generation password reset link for " + username);
    System.out.println(
        "Created password reset link: "
            + new PasswordResetLink().createPasswordReset(username, key));
  }
}
