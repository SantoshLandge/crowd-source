package com.crowdsource.userservice.entity;

import com.crowdsource.userservice.entity.enums.UserStatus;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users", uniqueConstraints = @UniqueConstraint(columnNames = "email"))
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email
    @NotBlank
    @Column(nullable = false, unique = true)
    private String email;

    @NotBlank
    @Column(nullable = false)
    private String password;  // BCrypt hash

    @Column(name = "display_name")
    private String displayName;         // User-friendly name (can be changed)

    @Column(name = "first_name")
    private String firstName;           // Optional

    @Column(name = "last_name")
    private String lastName;            // Optional

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "email_verified")
    @Builder.Default
    private Boolean emailVerified = false;  // Default to false      // For email verification flow

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    @OneToMany(mappedBy = "userId", cascade = CascadeType.REMOVE, fetch = FetchType.LAZY)
    private Set<RefreshToken> refreshTokens = new HashSet<>();

    public void addRole(Role role) {
        roles.add(role);
    }

    public void revokeAllRefreshTokens() {
        refreshTokens.forEach(t -> t.setRevoked(true));
    }

    // Helper: for CustomUserDetails
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return Stream.concat(
                        // ROLES (Spring convention)
                        roles.stream()
                                .map(role -> (GrantedAuthority) () -> "ROLE_" + role.getName()),

                        // Role Permissions
                        roles.stream()
                                .flatMap(role -> role.getPermissions().stream())
                                .map(p -> (GrantedAuthority) p::getName)
                )
                .collect(Collectors.toList());

    }

    public boolean isEnabled() {
        return status == UserStatus.ACTIVE;
    }
}