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

/**
 * This class is a user controller that exposes the endpoints
 * That the user can interact with
 */
public class UserResource
{
    //This Object is injected because of the required args constructor annotation
    private final UserService userService;

    /**
     * This method gets all users in the database
     * @return a list of users as json object
     */
    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers()
    {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    /**
     * This end point adds a user to the database
     * @param user to be added to the database
     * @return the added user
     */
    @PostMapping("/user/signup")
    public ResponseEntity<User> saveUser(@RequestBody User user)
    {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/user/signup").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    /**
     * This endpoint saves a role to the role table in the database
     * @param role to be saved
     * @return the saved role
     */
    @PostMapping("/role/save")
    public ResponseEntity<Role>saveRole(@RequestBody Role role)
    {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    /**
     * This endpoint finds user with specific id
     * @param id of the user to be found
     * @return the found user
     */
    @GetMapping("/users/{id}")
    public Optional<User> getUserWithId(@PathVariable Long id)
    {
        return userService.getUserById(id);
    }

    /**
     * This endpoint deletes users
     * @param id of the user to be deleted
     */
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id)
    {
        userService.deleteUser(id);
    }

    /**
     * This endpoint updates user
     * @param user to update
     * @return The updated user
     */
    @PutMapping("/users")
    public ResponseEntity<User> updateUser(@RequestBody User user)
    {
        return ResponseEntity.ok().body(userService.updateUser(user));
    }


}
