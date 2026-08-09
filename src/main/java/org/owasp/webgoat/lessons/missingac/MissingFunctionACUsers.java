/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import java.util.ArrayList;
import java.util.List;

import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.CurrentUsername;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

/** Created by jason on 1/5/17. */
@Controller
@AllArgsConstructor
@Slf4j
public class MissingFunctionACUsers {

  private final MissingAccessControlUserRepository userRepository;

  @GetMapping(path = {"access-control/users"})
  public ModelAndView listUsers(@CurrentUsername String username) {
    ModelAndView model = new ModelAndView();
    model.setViewName("list_users");
    // Same listing, same password hashes, only rendered as HTML instead of JSON - gating one
    // representation and not the other leaves the data exactly as exposed as before.
    if (!isAdmin(username)) {
      model.addObject("numUsers", 0);
      model.addObject("allUsers", new ArrayList<DisplayUser>());
      return model;
    }

    List<User> allUsers = userRepository.findAllUsers();
    model.addObject("numUsers", allUsers.size());
    // add display user objects in place of direct users
    List<DisplayUser> displayUsers = new ArrayList<>();
    for (User user : allUsers) {
      displayUsers.add(new DisplayUser(user, PASSWORD_SALT_SIMPLE));
    }
    model.addObject("allUsers", displayUsers);

    return model;
  }

  @GetMapping(
      path = {"access-control/users"},
      consumes = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersService(@CurrentUsername String username) {
    // The listing hands out every user's password hash, so it is an administrative view and has
    // to be gated like one - the same check the -admin-fix variant below already performs.
    if (!isAdmin(username)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    return ResponseEntity.ok(
        userRepository.findAllUsers().stream()
            .map(user -> new DisplayUser(user, PASSWORD_SALT_SIMPLE))
            .collect(Collectors.toList()));
  }

  @GetMapping(
      path = {"access-control/users-admin-fix"},
      consumes = "application/json")
  @ResponseBody
  public ResponseEntity<List<DisplayUser>> usersFixed(@CurrentUsername String username) {
    if (isAdmin(username)) {
      return ResponseEntity.ok(
          userRepository.findAllUsers().stream()
              .map(user -> new DisplayUser(user, PASSWORD_SALT_ADMIN))
              .collect(Collectors.toList()));
    }
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
  }

  private boolean isAdmin(String username) {
    var currentUser = userRepository.findByUsername(username);
    return currentUser != null && currentUser.isAdmin();
  }

  @PostMapping(
      path = {"access-control/users", "access-control/users-admin-fix"},
      consumes = "application/json",
      produces = "application/json")
  @ResponseBody
  public ResponseEntity<User> addUser(
      @RequestBody User newUser, @CurrentUsername String username) {
    // Creating accounts is an administrative action. Without this check anyone could register a
    // user, and because the request body binds straight onto the entity they could set admin on
    // it - handing themselves the privilege the check above is supposed to protect.
    if (!isAdmin(username)) {
      return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
    }
    // admin is never accepted from the request body; it is not a client-supplied attribute.
    newUser.setAdmin(false);
    try {
      userRepository.save(newUser);
      return ResponseEntity.ok(newUser);
    } catch (Exception ex) {
      log.error("Error creating new User", ex);
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    // @RequestMapping(path = {"user/{username}","/"}, method = RequestMethod.DELETE, consumes =
    // "application/json", produces = "application/json")
    // TODO implement delete method with id param and authorization

  }
}
