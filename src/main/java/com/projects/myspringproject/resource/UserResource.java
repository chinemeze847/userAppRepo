package com.projects.myspringproject.resource;

import com.projects.myspringproject.domain.Role;
import com.projects.myspringproject.domain.User;
import com.projects.myspringproject.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")

public class UserResource
{
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers()
    {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/signup")
    public ResponseEntity<User> saveUser(@RequestBody User user)
    {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/user/signup").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role>saveRole(@RequestBody Role role)
    {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @GetMapping("/users/{id}")
    public Optional<User> getUserWithId(@PathVariable Long id)
    {
        return userService.getUserById(id);
    }

    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id)
    {
        userService.deleteUser(id);
    }


}
