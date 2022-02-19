# User Application project

##Description : 
This is a program that allows users to be added , deleted , viewed ,
updated. It also allows roles to be added and removed from users.
This project also has security measures implemented both to filter , authenticate and
authorize only the right users to access specific resources.

##Usage
###domain package
This package holds my entities which are the Role and users

###User class
```import java.util.List;

/**this is a static import that enables the id of users
*to be automatically generated
*/
import static javax.persistence.GenerationType.AUTO;

@Entity  //This annotation specifies that this class is an entity in the database
@Data   //This removes the need for setters and getters because it handles it for us
@NoArgsConstructor  // it generates the no argument constructor
@AllArgsConstructor // it generates all arguments contructor
/**
 * The model for building a user
 */
public class User
{
    @Id
    @GeneratedValue(strategy = AUTO)
    private Long id;// the identifier of the users
    private String name; // the name of the users
    private String username; // the user name that will be used for authentication and authorization
    private String password; // the unique password of the user

    @ManyToMany(fetch = FetchType.EAGER) // This implies that each users can have many roles and each role can be assigned to multiple users
    private Collection<Role> roles = new ArrayList(); // the roles that each user has
}
```
####Role class
```
import javax.persistence.Id;

import static javax.persistence.GenerationType.AUTO;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
/**
 * The model for building a role
 */
public class Role
{
    @Id
    @GeneratedValue(strategy = AUTO)
    private Long id;
    private String name;
}
```
###Filter package
This is the package that holds all classes in charge of filtering request

####AuthFilter class
```
package com.projects.myspringproject.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
/**
 * This class filters request from the user
 */
public class AuthFilter extends UsernamePasswordAuthenticationFilter
{
    private final AuthenticationManager authenticationManager;

    //injecting the authentication manager via the constructor
    public AuthFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * This method authenticates a token when a user attempts to login
     * @param request from the user
     * @param response from the server or api
     * @return authentication token
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String psw = request.getParameter("password");
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, psw);

        return authenticationManager.authenticate(authenticationToken);
    }

    /**
     * This method is called if the user is authenticated successfully
     * @param request from the user
     * @param response from the api
     * @param chain
     * @param auth authentication
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain, Authentication auth) throws IOException, ServletException {
        User user = (User)auth.getPrincipal();
        Algorithm algo = Algorithm.HMAC256("secured".getBytes());

        //generates an access token for the user
        String access_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()* 10*60*1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algo);

        //generates a refresh token after the access token has expired
        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()* 50*60*1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algo);

        response.setHeader("access_token",access_token); // set the access_token in the response header
        response.setHeader("refresh_token",refresh_token);  // set refresh_token in the response header
    }
}

```
###Repository package
This package holds the repository interfaces for each domain

####User Repository
The user repository contains methods for performing CRUD operations, sorting and paginating data.
```
package com.projects.myspringproject.repository;

import com.projects.myspringproject.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository // This marks this class to be a repository class
@Transactional  // This enables all methods to be executed as a transaction that is 
it either fails or succeeds
/**
 * This is the user repository interface that has some methods already defined
 * for the service class to use
 */
public interface UserRepository extends JpaRepository<User, Long>
{
    User findByUsername(String username);//A method i will implement later for finding users by username
}
```
####Role Repository
```
package com.projects.myspringproject.repository;

import com.projects.myspringproject.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public interface RoleRepository extends JpaRepository<Role,Long>
{
    Role findByName(String name);
}

```
###Resource package
it contains the endpoints that users can interact with based on their roles.
This is because only users with roles of admins can add or remove users, normal
users are not given that permission
```
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

```
###Security package

####SecurityConfig class
It contains all the security configurations
```
package com.projects.myspringproject.security;

import com.projects.myspringproject.filter.AuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
/**
 * this is my security class that stands between my users and
 * my api to authenticate and authorize only users with certain permissions
 */
public class SecurityConfig extends WebSecurityConfigurerAdapter
{
    //injection of dependencies
    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * Thsis method configures the user detail service and the password encoder
     * @param auth the authentication builder
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);
    }

    /**
     * This method configures the permissions for various paths
     * @param http is the security guardian
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        AuthFilter authFilter = new AuthFilter(authenticationManager());
        authFilter.setFilterProcessesUrl("/api/login");
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests().antMatchers("/api/login/**").permitAll();
        http.authorizeRequests().antMatchers(GET,"/api/users/**").hasAnyAuthority("ROLE_USER");
        http.authorizeRequests().antMatchers(POST,"/user/signup/**").hasAnyAuthority("ROLE_ADMIN");
        http.authorizeRequests().anyRequest().permitAll();
        http.addFilter(authFilter);
    }

    /**
     * This method returns an authentication manager that manages all authentications
     * @return authentication manager
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception
    {
        return super.authenticationManager();
    }
}

```
###Service  package
This package holds the service class which interacts with the api directly 

####UserService class
This is an interface that defines the methods that will be used to interact with
the resource class. it uses the facade design pattern to enable loose coupling
```
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
```
####UserServiceImpl class
This class implements the methods in the service class 
```
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
```

###MySpringProjectApp
This is the class from which all others run just like the main class in java

