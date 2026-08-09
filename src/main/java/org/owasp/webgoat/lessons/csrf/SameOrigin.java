/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Decides whether a state-changing request was made from the application itself.
 *
 * <p>A browser attaches the session cookie to a cross-site request just as readily as to one the
 * user meant to make, so the cookie proves nothing about where the request came from. Origin, and
 * failing that Referer, is what carries that information, and a request that declares neither
 * cannot be shown to be same-origin - so it is not treated as one.
 */
final class SameOrigin {

  private SameOrigin() {}

  static boolean isSameOrigin(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      return false;
    }

    String origin = request.getHeader("Origin");
    if (origin != null && !origin.isBlank()) {
      return host.equals(hostOf(origin));
    }

    String referer = request.getHeader("Referer");
    if (referer != null && !referer.isBlank()) {
      return host.equals(hostOf(referer));
    }

    return false;
  }

  private static String hostOf(String url) {
    try {
      URI uri = new URI(url);
      if (uri.getHost() == null) {
        return null;
      }
      return uri.getPort() == -1 ? uri.getHost() : uri.getHost() + ":" + uri.getPort();
    } catch (URISyntaxException e) {
      return null;
    }
  }
}
