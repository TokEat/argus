-- Python EXP is replaced atomically by the Yaksha EXP workspace. Refuse the
-- migration when legacy user data exists so operators must export or remove it
-- deliberately because no implicit conversion can preserve Python execution meaning.
DO $$
DECLARE
    legacy_table TEXT;
    has_rows BOOLEAN;
BEGIN
    FOREACH legacy_table IN ARRAY ARRAY[
        'exploit_artifacts',
        'exploit_runs',
        'exploit_audits',
        'exploit_risk_waivers',
        'exploit_rules',
        'agent_pyenv_jobs'
    ] LOOP
        IF to_regclass('public.' || legacy_table) IS NOT NULL THEN
            EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I LIMIT 1)', legacy_table) INTO has_rows;
            IF has_rows THEN
                RAISE EXCEPTION
                    'legacy Python EXP data exists in table %; export or remove it manually before applying migration 530',
                    legacy_table;
            END IF;
        END IF;
    END LOOP;

    IF to_regclass('public.arsenals') IS NOT NULL THEN
        SELECT EXISTS (
            SELECT 1 FROM arsenals
            WHERE lower(trim(type)) IN ('exp', 'exploit')
            LIMIT 1
        ) INTO has_rows;
        IF has_rows THEN
            RAISE EXCEPTION
                'legacy Python EXP data exists in arsenals; export or remove rows with type exp/exploit before applying migration 530';
        END IF;
    END IF;
END
$$;

DROP TABLE IF EXISTS exploit_artifacts;
DROP TABLE IF EXISTS exploit_runs;
DROP TABLE IF EXISTS exploit_audits;
DROP TABLE IF EXISTS exploit_risk_waivers;
DROP TABLE IF EXISTS exploit_rules;
DROP TABLE IF EXISTS agent_pyenv_jobs;

ALTER TABLE IF EXISTS rule_catalog_bootstraps DROP COLUMN IF EXISTS exploit_count;
