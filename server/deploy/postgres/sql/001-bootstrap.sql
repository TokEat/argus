-- Bootstrap role and database for the dddd control plane.
-- Required psql variables:
--   app_db_name
--   app_db_user
--   app_db_password

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_db_user') THEN
        EXECUTE format(
            'ALTER ROLE %I WITH LOGIN PASSWORD %L',
            :'app_db_user',
            :'app_db_password'
        );
    ELSE
        EXECUTE format(
            'CREATE ROLE %I WITH LOGIN PASSWORD %L',
            :'app_db_user',
            :'app_db_password'
        );
    END IF;
END
$$;

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
