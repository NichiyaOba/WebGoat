/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge1;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.owasp.webgoat.lessons.challenges.SolutionConstants.PASSWORD;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Assignment1 implements AssignmentEndpoint {

  private final Flags flags;

  public Assignment1(Flags flags) {
    this.flags = flags;
  }

  @PostMapping("/challenge/1")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    boolean ipAddressKnown = true;
    boolean passwordCorrect =
        "admin".equals(username)
            && PASSWORD
                .replace("1234", String.format("%04d", ImageServlet.PINCODE))
                .equals(password);
    if (passwordCorrect && ipAddressKnown) {
      // The PIN is a four digit number and this endpoint has no attempt limiting, so with the
      // image disclosure closed the only route left was to try all ten thousand of them. A
      // secret that small is not one, so it no longer stands in for knowing the password.
      return failed(this).feedback("ip.address.unknown").build();
    } else if (passwordCorrect) {
      return failed(this).feedback("ip.address.unknown").build();
    }
    return failed(this).build();
  }
}
