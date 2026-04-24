package com.crowdsource.userservice.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "permissions", uniqueConstraints = @UniqueConstraint(columnNames = "name"))
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(nullable = false)
    private String name;  // e.g., "read:users"

    @Column(name = "resource")  // e.g., "users"
    private String resource;

    @Column(name = "action")    // e.g., "read"
    private String action;

}
