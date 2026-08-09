/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.advanced;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqlInjectionLesson6b implements AssignmentEndpoint {
  private final LessonDataSource dataSource;

  /**
   * dave's password ships as a fixed value in the seed data, so it is published wherever this
   * source is. Rotating it per run means the only way to learn it is to read it out of the
   * database, which is the step this check is supposed to be evidence of.
   */
  private final String davesPassword = UUID.randomUUID().toString();

  public SqlInjectionLesson6b(LessonDataSource dataSource) {
    this.dataSource = dataSource;
    rotateDavesPassword();
  }

  private void rotateDavesPassword() {
    try (Connection connection = dataSource.getConnection();
        var statement =
            connection.prepareStatement(
                "UPDATE user_system_data SET password = ? WHERE user_name = 'dave'")) {
      statement.setString(1, davesPassword);
      statement.executeUpdate();
    } catch (SQLException e) {
      // The lesson database is provisioned per user; if it is not reachable at construction time
      // the seeded value stays and getPassword below keeps comparing against whatever is stored.
    }
  }

  @PostMapping("/SqlInjectionAdvanced/attack6b")
  @ResponseBody
  public AttackResult completed(@RequestParam String userid_6b) throws IOException {
    if (userid_6b.equals(getPassword())) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  protected String getPassword() {
    String password = "dave";
    try (Connection connection = dataSource.getConnection()) {
      String query = "SELECT password FROM user_system_data WHERE user_name = 'dave'";
      try {
        Statement statement =
            connection.createStatement(
                ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        ResultSet results = statement.executeQuery(query);

        if (results != null && results.first()) {
          password = results.getString("password");
        }
      } catch (SQLException sqle) {
        sqle.printStackTrace();
        // do nothing
      }
    } catch (Exception e) {
      e.printStackTrace();
      // do nothing
    }
    return (password);
  }
}
