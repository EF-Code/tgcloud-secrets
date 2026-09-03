-- Runtime roles must never inherit the ability to create objects in the
-- application schema. Role-specific table grants are supplied by ops SQL.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
