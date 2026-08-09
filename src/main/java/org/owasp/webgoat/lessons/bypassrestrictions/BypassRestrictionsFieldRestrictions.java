/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.Set;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  private static final Set<String> ALLOWED_OPTIONS = Set.of("option1", "option2");
  private static final Set<String> ALLOWED_CHECKBOX_VALUES = Set.of("on", "off");
  private static final int SHORT_INPUT_MAX_LENGTH = 5;
  private static final String READ_ONLY_VALUE = "change";

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // The restrictions the form advertises - a fixed set of options, a maximum length, a
    // read-only value - are only hints to the browser. Anything that reaches this method came
    // over the wire and has to be checked again here, where the client cannot reach.
    if (!ALLOWED_OPTIONS.contains(select)
        || !ALLOWED_OPTIONS.contains(radio)
        || !ALLOWED_CHECKBOX_VALUES.contains(checkbox)
        || shortInput.length() > SHORT_INPUT_MAX_LENGTH
        || !READ_ONLY_VALUE.equals(readOnlyInput)) {
      return failed(this).output("Submitted values violate the field restrictions").build();
    }

    if (select.equals("option1") || select.equals("option2")) {
      return failed(this).build();
    }
    if (radio.equals("option1") || radio.equals("option2")) {
      return failed(this).build();
    }
    if (checkbox.equals("on") || checkbox.equals("off")) {
      return failed(this).build();
    }
    if (shortInput.length() <= 5) {
      return failed(this).build();
    }
    if ("change".equals(readOnlyInput)) {
      return failed(this).build();
    }
    return success(this).build();
  }
}
