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
