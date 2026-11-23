package com.crowdsource.userservice.repository;

import java.util.UUID;
import com.crowdsource.userservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // Core auth lookup (email as username)
    Optional<User> findByEmail(String email);

    // Check if user exists for registration
    boolean existsByEmail(String email);

}
