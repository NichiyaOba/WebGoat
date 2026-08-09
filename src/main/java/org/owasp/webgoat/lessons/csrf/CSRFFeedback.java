/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-feedback-hint1", "csrf-feedback-hint2", "csrf-feedback-hint3"})
public class CSRFFeedback implements AssignmentEndpoint {

  private final LessonSession userSessionData;
  private final ObjectMapper objectMapper;

  public CSRFFeedback(LessonSession userSessionData, ObjectMapper objectMapper) {
    this.userSessionData = userSessionData;
    this.objectMapper = objectMapper;
  }

  @PostMapping(
      value = "/csrf/feedback/message",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(HttpServletRequest request, @RequestBody String feedback) {
    try {
      objectMapper.enable(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS);
      objectMapper.enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY);
      objectMapper.enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES);
      objectMapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
      objectMapper.readValue(feedback.getBytes(), Map.class);
    } catch (IOException e) {
      return failed(this).feedback(ExceptionUtils.getStackTrace(e)).build();
    }
    // Posting feedback changes state, so it is only accepted from this application. The session
    // cookie rides along on a cross-site post exactly as it does on a real one, which is why the
    // previous version - cookie present, text/plain body, Referer pointing elsewhere - described
    // a successful CSRF rather than a legitimate request.
    if (!SameOrigin.isSameOrigin(request)) {
      return failed(this).output("Request did not originate from this application").build();
    }

    // The flag was the reward for a cross-site post landing here. Now that only same-origin posts
    // are accepted, there is no cross-site post to reward - and handing the flag to an ordinary
    // same-origin submission would just move the giveaway, not remove it. Feedback is accepted;
    // no secret is returned.
    return failed(this).output("Thanks for your feedback").build();
  }

  @PostMapping(path = "/csrf/feedback", produces = "application/json")
  @ResponseBody
  public AttackResult flag(@RequestParam("confirmFlagVal") String flag) {
    if (flag.equals(userSessionData.getValue("csrf-feedback"))) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  /*
   * Solution:
   * <form name="attack" enctype="text/plain" action="http://localhost:8080/WebGoat/csrf/feedback/message" METHOD="POST">
   *    <!-- Construct valid JSON data: {name: "HackHuang", email: "email@example.com", subject: "suggestions", message: "Fixed the invalid solution="} -->
   *    <input type="hidden" name='{"name": "HackHuang", "email": "email@example.com", "subject": "suggestions","message":"Fixed the invalid solution', value='"}'>
   * </form>
   * <script>document.attack.submit();</script>
   */

}
