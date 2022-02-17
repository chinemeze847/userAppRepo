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
