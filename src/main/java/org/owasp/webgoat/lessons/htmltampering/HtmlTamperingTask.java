/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.math.BigDecimal;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  private static final BigDecimal UNIT_PRICE = new BigDecimal("2999.99");

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    BigDecimal quantity;
    try {
      quantity = new BigDecimal(QTY);
    } catch (NumberFormatException e) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }

    BigDecimal submittedTotal;
    try {
      submittedTotal = new BigDecimal(Total);
    } catch (NumberFormatException e) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }

    // What the order costs is a server-side fact. The submitted total used to be believed, so a
    // tampered form field decided the price. It is recomputed here, and a submission that
    // disagrees with it is rejected instead of being charged as sent.
    BigDecimal chargedTotal = UNIT_PRICE.multiply(quantity);
    if (submittedTotal.compareTo(chargedTotal) != 0) {
      return failed(this)
          .feedback("html-tampering.tamper.failure")
          .output("Order total is " + chargedTotal)
          .build();
    }

    if (chargedTotal.compareTo(submittedTotal.add(BigDecimal.ONE)) > 0) {
      return success(this).feedback("html-tampering.tamper.success").build();
    }
    return failed(this).feedback("html-tampering.tamper.failure").build();
  }
}
