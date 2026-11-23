package com.crowdsource.userservice.repository;

import java.util.UUID;
import com.crowdsource.userservice.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    // Find by name (e.g., "ADMIN")
    Optional<Role> findByName(String name);

}
