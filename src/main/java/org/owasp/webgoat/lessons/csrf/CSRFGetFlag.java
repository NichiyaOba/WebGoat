/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    // A request that cannot be shown to come from this application is exactly the one that must
    // not be honoured. Previously a missing Referer - the default for anything that is not a
    // browser following a link - was read as proof of a cross-site request and rewarded with the
    // flag, so the endpoint handed out its secret to whoever asked without one.
    response.put("success", false);
    response.put(
        "message",
        SameOrigin.isSameOrigin(req)
            ? "Appears the request came from the original host"
            : "Request did not originate from this application");
    response.put("flag", null);
    return response;
  }
}
