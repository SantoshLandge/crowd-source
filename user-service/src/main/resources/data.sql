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
-- ROLE_USER (id=1): profile access
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 1);
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 2);
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 4);
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 9);

-- ROLE_ORGANIZER (id=2): event management
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 6);
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 7);
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 9);
INSERT INTO role_permissions (role_id, permission_id) VALUES (2, 4);

-- ROLE_ADMIN (id=3): full access
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 5);
INSERT INTO role_permissions (role_id, permission_id) VALUES (3, 10);

-- =====================================================
-- TEST USERS
-- =====================================================
-- Regular User (id will be auto-generated if using identity column)
INSERT INTO users (display_name, email, password, status, created_at) VALUES ('User', 'user@crowdsource.com', '{noop}user', 'ACTIVE', CURRENT_TIMESTAMP);
INSERT INTO user_roles (user_id, role_id) VALUES ((SELECT id FROM users WHERE email = 'user@crowdsource.com'), 1);

-- Organizer User
INSERT INTO users (display_name, email, password, status, created_at) VALUES ('Organizer', 'organizer@crowdsource.com', '{noop}organizer', 'ACTIVE', CURRENT_TIMESTAMP);
INSERT INTO user_roles (user_id, role_id) VALUES ((SELECT id FROM users WHERE email = 'organizer@crowdsource.com'), 2);

-- Admin User
INSERT INTO users (display_name, email, password, status, created_at) VALUES ('Admin', 'admin@crowdsource.com', '{noop}admin', 'ACTIVE', CURRENT_TIMESTAMP);
INSERT INTO user_roles (user_id, role_id) VALUES ((SELECT id FROM users WHERE email = 'admin@crowdsource.com'), 3);