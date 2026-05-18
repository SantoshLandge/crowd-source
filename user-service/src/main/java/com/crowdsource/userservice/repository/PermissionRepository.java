package com.crowdsource.userservice.repository;

import com.crowdsource.userservice.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    // Find by name (e.g., "read:users")
    Optional<Permission> findByName(String name);

    // All permissions for admin management
    List<Permission> findAllByOrderByName();

    // Scoped by resource/action
    List<Permission> findByResourceAndAction(String resource, String action);
}
