-- =====================================================
-- ROLES
-- =====================================================
INSERT INTO roles (id, name) VALUES (1, 'USER');
INSERT INTO roles (id, name) VALUES (2, 'ORGANIZER');
INSERT INTO roles (id, name) VALUES (3, 'ADMIN');

-- =====================================================
-- PERMISSIONS
-- =====================================================
INSERT INTO permissions (id, name, resource, action) VALUES (1, 'create:user', 'user', 'create');
INSERT INTO permissions (id, name, resource, action) VALUES (2, 'update:user', 'user', 'update');
INSERT INTO permissions (id, name, resource, action) VALUES (3, 'delete:user', 'user', 'delete');
INSERT INTO permissions (id, name, resource, action) VALUES (4, 'read:user', 'user', 'read');
INSERT INTO permissions (id, name, resource, action) VALUES (5, 'manage:users', 'users', 'manage');
INSERT INTO permissions (id, name, resource, action) VALUES (6, 'create:event', 'event', 'create');
INSERT INTO permissions (id, name, resource, action) VALUES (7, 'update:event', 'event', 'update');
INSERT INTO permissions (id, name, resource, action) VALUES (8, 'delete:event', 'event', 'delete');
INSERT INTO permissions (id, name, resource, action) VALUES (9, 'read:event', 'event', 'read');
INSERT INTO permissions (id, name, resource, action) VALUES (10, 'manage:events', 'events', 'manage');

-- =====================================================
-- ROLE PERMISSIONS
-- =====================================================
-- USER: own profile + read events
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 1);
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 2);
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 4);
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 9);

-- ORGANIZER: event management
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 6);
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 7);
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 9);
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 4);

-- ADMIN: everything (previously only manage:*, so read:user / update:user based checks failed for admins)
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 1);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 2);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 3);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 4);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 5);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 6);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 7);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 8);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 9);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 10);

-- Demo users are created (with BCrypt hashes) by DevDataSeeder in non-prod profiles.
