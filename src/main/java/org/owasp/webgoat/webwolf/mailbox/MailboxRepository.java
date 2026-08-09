/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.mailbox;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author nbaars
 * @since 8/17/17.
 */
public interface MailboxRepository extends JpaRepository<Email, String> {

  List<Email> findByRecipientOrderByTimeDesc(String recipient);

  /** Single bulk statement, so the cost does not grow with the size of the mailbox. */
  @Modifying
  @Transactional
  @Query("delete from Email e where e.recipient = :recipient")
  void deleteByRecipient(@Param("recipient") String recipient);
}
