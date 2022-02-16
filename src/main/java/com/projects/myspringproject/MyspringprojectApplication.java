package com.projects.myspringproject;

import com.projects.myspringproject.domain.Role;
import com.projects.myspringproject.domain.User;
import com.projects.myspringproject.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class MyspringprojectApplication
{

	public static void main(String[] args)
	{
		SpringApplication.run(MyspringprojectApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	@Bean
	CommandLineRunner runner(UserService userService){
		return args ->
		{
			userService.saveRole(new Role(null,"ROLE_USER"));
			userService.saveRole(new Role(null,"ROLE_MANAGER"));
			userService.saveRole(new Role(null,"ROLE_ADMIN"));
			userService.saveRole(new Role(null,"ROLE_DIRECTOR"));

			userService.saveUser(new User(null,"John Smith","John","23424",new ArrayList<>()));
			userService.saveUser(new User(null,"Maria carey","Maria","11878",new ArrayList<>()));
			userService.saveUser(new User(null,"Henry Ford","Ford","11111",new ArrayList<>()));
			userService.saveUser(new User(null,"Max Williams","Max","87373",new ArrayList<>()));

			userService.addUserRole("John","ROLE_USER");
			userService.addUserRole("John","ROLE_MANAGER");
			userService.addUserRole("Maria","ROLE_ADMIN");
			userService.addUserRole("Max","ROLE_USER");
			userService.addUserRole("Max","ROLE_ADMIN");
			userService.addUserRole("Max","ROLE_DIRECTOR");


		};
	}

}
