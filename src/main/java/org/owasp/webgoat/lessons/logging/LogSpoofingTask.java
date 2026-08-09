/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output(username).build();
    }
    // The entry is rendered as HTML, so the name has to reach it as text. Stripping CR/LF is not
    // enough: the payload types the five characters "<br/>" itself, and unescaped they become a
    // real line break that invents a log record. Escaping is what makes the value inert, and the
    // check below then runs on the value that is actually rendered - the same value the reader
    // sees - rather than on the raw parameter.
    username = username.replaceAll("[\\r\\n]", "");
    String rendered = HtmlUtils.htmlEscape(username);
    if (username.contains("<p>") || username.contains("<div>")) {
      return failed(this).output("Try to think of something simple ").build();
    }
    // indexOf returns -1 when there is no break at all, and -1 sorts before every real index, so
    // the break has to be shown to exist before its position means anything.
    int lineBreak = rendered.indexOf("<br/>");
    if (lineBreak >= 0 && lineBreak < rendered.indexOf("admin")) {
      return success(this).output(rendered).build();
    }
    return failed(this).output(rendered).build();
  }
}
