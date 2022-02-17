package com.projects.myspringproject.service;

import com.projects.myspringproject.domain.Role;
import com.projects.myspringproject.domain.User;
import java.util.List;
import java.util.Optional;

/**
 * This class is a facade that interfaces with the user controller
 * on behalf of the models
 */
public interface UserService
{
    User saveUser(User user);
    Role saveRole(Role role);
    void addUserRole(String username, String roleName);
    User getUser(String user);
    List<User> getUsers();
    Optional<User> getUserById(Long id);
    void deleteUser(Long id);
    User updateUser(User user);
}
