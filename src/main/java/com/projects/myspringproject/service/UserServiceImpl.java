package com.projects.myspringproject.service;

import com.projects.myspringproject.domain.Role;
import com.projects.myspringproject.domain.User;
import com.projects.myspringproject.repository.RoleRepository;
import com.projects.myspringproject.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * This annotations specify that this class is a service class and requires
 * the constructor with argument to properly inject the dependencies
 */
@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
/**
 * This class provides implementation for the methods
 * defined in the user Service interface
 */
public class UserServiceImpl implements UserService, UserDetailsService
{
    //dependency injection of the repositories
    private final UserRepository userRepository;
    private final  RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * This method saves a user to the database
     * @param user to be saved
     * @return the saved user
     */
    @Override
    public User saveUser(User user)
    {
        log.info("Adding new user {} to database", user);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    /**
     * This method saves a role to db
     * @param role to be saved
     * @return saved role
     */
    @Override
    public Role saveRole(Role role)
    {
        log.info("Adding new role {} to database", role);
        return roleRepository.save(role);
    }

    /**
     * this method adds a role to a user
     * @param username of the user
     * @param roleName of the role to add to the user
     */
    @Override
    public void addUserRole(String username, String roleName)
    {
        //logs information to the console
        log.info("Adding new  role {} to {} in the database", roleName,username);

        //get the user with specific username
        User user = userRepository.findByUsername(username);

        //get the role with specific rolename
        Role role = roleRepository.findByName(roleName);

        //add the role to the user
        user.getRoles().add(role);
    }

    /**
     * this method gets a specific user
     * @param user to get
     * @return the user
     */
    @Override
    public User getUser(String user)
    {
        //log informantion to console
        log.info("Fetching  user {} from database", user);

        //find a user with a specific username
        return userRepository.findByUsername(user);
    }

    /**
     * This method gets a list of users
     * @return users
     */
    @Override
    public List<User> getUsers()
    {
        //logs info to the console
        log.info("Fetching all users from database");

        //it finds all users
        return  userRepository.findAll();
    }

    /**
     * This method loads user with specific username a
     * @param username of the user to load
     * @return user details
     * @throws UsernameNotFoundException if the user is not found
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        //get the user with the specific username
        User user = userRepository.findByUsername(username);

        //check if the user is null
        if(user == null){
            log.error("user not found in database");
            throw new UsernameNotFoundException("user not found in database");
        }else{
            log.info("user {} found in database",user);
        }
        //initialize a collection of simple granted authorities
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        //loop through the roles of the user and add it to the authorities object
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });

        //this returns the username, password and authorities of a specific user
        return new org.springframework.security.core
                .userdetails.User(user.getUsername(),user.getPassword(),authorities);
    }

    /**
     * This method retrieves a user with specific if
     * @param Id of user to be retrieved
     * @return the user
     */
    @Override
    public Optional<User> getUserById(Long Id)
    {
        return userRepository.findById(Id);
    }

    /**
     * This method deletes a user
     * @param id of user to delete
     */
    @Override
    public void deleteUser(Long id)
    {
        userRepository.deleteById(id);
    }

    /**
     * This method updates a user
     * @param user to be updated
     * @return updated user
     */
    @Override
    public User updateUser(User user)
    {
        return userRepository.save(user);
    }
}
