package com.pitagon.repository;

import com.pitagon.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.Optional;

public interface IRoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(Role.ERole name);
}
