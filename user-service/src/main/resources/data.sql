-- =====================================================
-- ROLES (fixed UUIDs so role_permissions can reference them; entity ids are UUID v7)
-- =====================================================
INSERT INTO roles (id, name) VALUES ('01980000-0001-7000-8000-000000000001', 'USER');
INSERT INTO roles (id, name) VALUES ('01980000-0001-7000-8000-000000000002', 'ORGANIZER');
INSERT INTO roles (id, name) VALUES ('01980000-0001-7000-8000-000000000003', 'ADMIN');

-- =====================================================
-- PERMISSIONS
-- =====================================================
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000001', 'create:user', 'user', 'create');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000002', 'update:user', 'user', 'update');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000003', 'delete:user', 'user', 'delete');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000004', 'read:user', 'user', 'read');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000005', 'manage:users', 'users', 'manage');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000006', 'create:event', 'event', 'create');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000007', 'update:event', 'event', 'update');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000008', 'delete:event', 'event', 'delete');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-000000000009', 'read:event', 'event', 'read');
INSERT INTO permissions (id, name, resource, action) VALUES ('01980000-0002-7000-8000-00000000000a', 'manage:events', 'events', 'manage');

-- =====================================================
-- ROLE PERMISSIONS
-- =====================================================
-- USER: own profile + read events
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000001', '01980000-0002-7000-8000-000000000001');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000001', '01980000-0002-7000-8000-000000000002');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000001', '01980000-0002-7000-8000-000000000004');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000001', '01980000-0002-7000-8000-000000000009');

-- ORGANIZER: event management
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000002', '01980000-0002-7000-8000-000000000006');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000002', '01980000-0002-7000-8000-000000000007');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000002', '01980000-0002-7000-8000-000000000009');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000002', '01980000-0002-7000-8000-000000000004');

-- ADMIN: everything (previously only manage:*, so read:user / update:user based checks failed for admins)
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000001');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000002');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000003');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000004');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000005');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000006');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000007');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000008');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-000000000009');
INSERT INTO role_permissions (role_id, permission_id) VALUES ('01980000-0001-7000-8000-000000000003', '01980000-0002-7000-8000-00000000000a');

-- Demo users are created (with BCrypt hashes) by DevDataSeeder in non-prod profiles.
