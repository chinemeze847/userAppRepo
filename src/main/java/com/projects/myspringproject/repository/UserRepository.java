package com.projects.myspringproject.repository;

import com.projects.myspringproject.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional
public interface UserRepository extends JpaRepository<User, Long>
{
    User findByUsername(String username);
}
