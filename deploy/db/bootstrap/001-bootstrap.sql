-- Bootstrap role and database for the Argus control plane.
-- Required psql variables:
--   app_db_name
--   app_db_user
--   app_db_password

SELECT format(
    'CREATE ROLE %I WITH LOGIN PASSWORD %L',
    :'app_db_user',
    :'app_db_password'
)
WHERE NOT EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = :'app_db_user'
)
\gexec

SELECT format(
    'ALTER ROLE %I WITH LOGIN PASSWORD %L',
    :'app_db_user',
    :'app_db_password'
)
WHERE EXISTS (
    SELECT 1
    FROM pg_roles
    WHERE rolname = :'app_db_user'
)
\gexec

SELECT format(
    'CREATE DATABASE %I WITH OWNER %I ENCODING %L TEMPLATE template0',
    :'app_db_name',
    :'app_db_user',
    'UTF8'
)
WHERE NOT EXISTS (
    SELECT 1
    FROM pg_database
    WHERE datname = :'app_db_name'
)
\gexec

SELECT format(
    'ALTER DATABASE %I OWNER TO %I',
    :'app_db_name',
    :'app_db_user'
)
\gexec

SELECT format(
    'GRANT ALL PRIVILEGES ON DATABASE %I TO %I',
    :'app_db_name',
    :'app_db_user'
)
\gexec
