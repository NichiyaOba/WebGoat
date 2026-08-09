/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@AssignmentHints({
  "client.side.filtering.free.hint1",
  "client.side.filtering.free.hint2",
  "client.side.filtering.free.hint3"
})
public class ClientSideFilteringFreeAssignment implements AssignmentEndpoint {
  public static final String SUPER_COUPON_CODE = "get_it_for_free";

  private final ShopEndpoint shop;

  public ClientSideFilteringFreeAssignment(ShopEndpoint shop) {
    this.shop = shop;
  }

  @PostMapping("/clientSideFiltering/getItForFree")
  @ResponseBody
  public AttackResult completed(@RequestParam String checkoutCode) {
    // Checkout used to compare the submitted code against a constant of its own, so it granted a
    // 100% discount for a code the coupon store does not recognise. The store is the authority on
    // which coupons exist and what they are worth, so the discount is looked up there.
    if (shop.discountFor(checkoutCode) >= 100) {
      return success(this).build();
    }
    return failed(this).build();
  }
}
