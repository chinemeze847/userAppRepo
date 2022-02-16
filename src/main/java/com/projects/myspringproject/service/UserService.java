package com.projects.myspringproject.service;

import com.projects.myspringproject.domain.Role;
import com.projects.myspringproject.domain.User;
import java.util.List;
import java.util.Optional;

public interface UserService
{
    User saveUser(User user);
    Role saveRole(Role role);
    void addUserRole(String username, String roleName);
    User getUser(String user);
    List<User> getUsers();
    Optional<User> getUserById(Long id);
    void deleteUser(Long id);
}
