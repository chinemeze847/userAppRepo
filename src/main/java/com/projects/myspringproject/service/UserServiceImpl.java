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

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService
{
    private final UserRepository userRepository;
    private final  RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public User saveUser(User user)
    {
        log.info("Adding new user {} to database", user);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role)
    {
        log.info("Adding new role {} to database", role);
        return roleRepository.save(role);
    }

    @Override
    public void addUserRole(String username, String roleName)
    {
        log.info("Adding new  role {} to {} in the database", roleName,username);
        User user = userRepository.findByUsername(username);
        Role role = roleRepository.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String user)
    {
        log.info("Fetching  user {} from database", user);
        return userRepository.findByUsername(user);
    }

    @Override
    public List<User> getUsers()
    {
        log.info("Fetching all users from database");
        return  userRepository.findAll();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        User user = userRepository.findByUsername(username);
        if(user == null){
            log.error("user not found in database");
            throw new UsernameNotFoundException("user not found in database");
        }else{
            log.info("user {} found in database",user);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        return new org.springframework.security.core
                .userdetails.User(user.getUsername(),user.getPassword(),authorities);
    }

    @Override
    public Optional<User> getUserById(Long Id)
    {
        return userRepository.findById(Id);
    }

    @Override
    public void deleteUser(Long id)
    {
        userRepository.deleteById(id);
    }
}
