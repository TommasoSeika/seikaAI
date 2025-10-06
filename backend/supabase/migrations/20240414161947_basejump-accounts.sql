-- =====================================================================
-- Basejump Accounts - Fixed Full Version
-- Includes missing helper functions:
--   basejump.trigger_set_timestamps()
--   basejump.trigger_set_user_tracking()
-- =====================================================================

CREATE SCHEMA IF NOT EXISTS basejump;

-- ---------------------------------------------------------------------
-- Function: basejump.trigger_set_timestamps()
-- Automatically sets created_at and updated_at timestamps
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION basejump.trigger_set_timestamps()
RETURNS TRIGGER AS
$$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.created_at = COALESCE(NEW.created_at, NOW());
        NEW.updated_at = COALESCE(NEW.updated_at, NOW());
    ELSIF TG_OP = 'UPDATE' THEN
        NEW.updated_at = NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------
-- Function: basejump.trigger_set_user_tracking()
-- Tracks created_by and updated_by based on current user
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION basejump.trigger_set_user_tracking()
RETURNS TRIGGER AS
$$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.created_by = COALESCE(NEW.created_by, auth.uid());
        NEW.updated_by = COALESCE(NEW.updated_by, auth.uid());
    ELSIF TG_OP = 'UPDATE' THEN
        NEW.updated_by = auth.uid();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------
-- Function: basejump.is_set(key TEXT)
-- Used in policy checks for configuration flags
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION basejump.is_set(key TEXT)
RETURNS BOOLEAN AS
$$
DECLARE
    val BOOLEAN;
BEGIN
    SELECT (value::BOOLEAN) INTO val
    FROM basejump.config
    WHERE name = key;
    RETURN COALESCE(val, FALSE);
END;
$$ LANGUAGE plpgsql;

-- =====================================================================
-- Section - Accounts
-- =====================================================================

DO
$$
BEGIN
    -- create ENUM only if not exists
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE t.typname = 'account_role'
        AND n.nspname = 'basejump'
    ) THEN
        CREATE TYPE basejump.account_role AS ENUM ('owner', 'member');
    END IF;
END;
$$;

-- ---------------------------------------------------------------------
-- Table: basejump.accounts
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS basejump.accounts (
    id uuid UNIQUE NOT NULL DEFAULT extensions.uuid_generate_v4(),
    primary_owner_user_id uuid REFERENCES auth.users NOT NULL DEFAULT auth.uid(),
    name TEXT,
    slug TEXT UNIQUE,
    personal_account BOOLEAN DEFAULT FALSE NOT NULL,
    updated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ,
    created_by uuid REFERENCES auth.users,
    updated_by uuid REFERENCES auth.users,
    private_metadata JSONB DEFAULT '{}'::JSONB,
    public_metadata JSONB DEFAULT '{}'::JSONB,
    PRIMARY KEY (id)
);

ALTER TABLE basejump.accounts
    ADD CONSTRAINT basejump_accounts_slug_null_if_personal_account_true CHECK (
        (personal_account = TRUE AND slug IS NULL)
        OR (personal_account = FALSE AND slug IS NOT NULL)
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE basejump.accounts TO authenticated, service_role;

-- ---------------------------------------------------------------------
-- Protect account fields from normal users
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION basejump.protect_account_fields()
RETURNS TRIGGER AS
$$
BEGIN
    IF current_user IN ('authenticated', 'anon') THEN
        IF NEW.id <> OLD.id
           OR NEW.personal_account <> OLD.personal_account
           OR NEW.primary_owner_user_id <> OLD.primary_owner_user_id THEN
            RAISE EXCEPTION 'You do not have permission to update this field';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER basejump_protect_account_fields
BEFORE UPDATE ON basejump.accounts
FOR EACH ROW
EXECUTE FUNCTION basejump.protect_account_fields();

-- ---------------------------------------------------------------------
-- Slugify function
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION basejump.slugify_account_slug()
RETURNS TRIGGER AS
$$
BEGIN
    IF NEW.slug IS NOT NULL THEN
        NEW.slug = lower(regexp_replace(NEW.slug, '[^a-zA-Z0-9-]+', '-', 'g'));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER basejump_slugify_account_slug
BEFORE INSERT OR UPDATE ON basejump.accounts
FOR EACH ROW
EXECUTE FUNCTION basejump.slugify_account_slug();

-- ---------------------------------------------------------------------
-- Row-Level Security + Timestamps + User Tracking
-- ---------------------------------------------------------------------
ALTER TABLE basejump.accounts ENABLE ROW LEVEL SECURITY;

CREATE TRIGGER basejump_set_accounts_timestamp
BEFORE INSERT OR UPDATE ON basejump.accounts
FOR EACH ROW
EXECUTE PROCEDURE basejump.trigger_set_timestamps();

CREATE TRIGGER basejump_set_accounts_user_tracking
BEFORE INSERT OR UPDATE ON basejump.accounts
FOR EACH ROW
EXECUTE PROCEDURE basejump.trigger_set_user_tracking();

-- ---------------------------------------------------------------------
-- Table: basejump.account_user
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS basejump.account_user (
    user_id uuid REFERENCES auth.users ON DELETE CASCADE NOT NULL,
    account_id uuid REFERENCES basejump.accounts ON DELETE CASCADE NOT NULL,
    account_role basejump.account_role NOT NULL,
    CONSTRAINT account_user_pkey PRIMARY KEY (user_id, account_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE basejump.account_user TO authenticated, service_role;

ALTER TABLE basejump.account_user ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------
-- Trigger: add current user to new account
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION basejump.add_current_user_to_new_account()
RETURNS TRIGGER AS
$$
BEGIN
    IF NEW.primary_owner_user_id = auth.uid() THEN
        INSERT INTO basejump.account_user (account_id, user_id, account_role)
        VALUES (NEW.id, auth.uid(), 'owner');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER basejump_add_current_user_to_new_account
AFTER INSERT ON basejump.accounts
FOR EACH ROW
EXECUTE FUNCTION basejump.add_current_user_to_new_account();

-- ---------------------------------------------------------------------
-- User creation trigger to create personal account
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION basejump.run_new_user_setup()
RETURNS TRIGGER AS
$$
DECLARE
    first_account_id uuid;
    generated_user_name TEXT;
BEGIN
    IF NEW.email IS NOT NULL THEN
        generated_user_name := split_part(NEW.email, '@', 1);
    END IF;

    INSERT INTO basejump.accounts (name, primary_owner_user_id, personal_account, id)
    VALUES (generated_user_name, NEW.id, TRUE, NEW.id)
    RETURNING id INTO first_account_id;

    INSERT INTO basejump.account_user (account_id, user_id, account_role)
    VALUES (first_account_id, NEW.id, 'owner');

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE PROCEDURE basejump.run_new_user_setup();

-- ---------------------------------------------------------------------
-- Function: basejump.has_role_on_account
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION basejump.has_role_on_account(
    account_id uuid,
    user_id uuid,
    roles basejump.account_role[]
)
RETURNS BOOLEAN AS
$$
DECLARE
    result BOOLEAN;
BEGIN
    SELECT TRUE INTO result
    FROM basejump.account_user
    WHERE account_user.account_id = has_role_on_account.account_id
      AND account_user.user_id = has_role_on_account.user_id
      AND account_user.account_role = ANY(roles)
    LIMIT 1;

    RETURN COALESCE(result, FALSE);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ---------------------------------------------------------------------
-- RLS Policies
-- ---------------------------------------------------------------------
CREATE POLICY basejump_accounts_select_policy
ON basejump.accounts
FOR SELECT USING (
    basejump.has_role_on_account(id, auth.uid(), ARRAY['owner', 'member'])
);

CREATE POLICY basejump_accounts_update_policy
ON basejump.accounts
FOR UPDATE USING (
    basejump.has_role_on_account(id, auth.uid(), ARRAY['owner'])
);

CREATE POLICY basejump_accounts_insert_policy
ON basejump.accounts
FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY basejump_account_user_select_policy
ON basejump.account_user
FOR SELECT USING (
    basejump.has_role_on_account(account_id, auth.uid(), ARRAY['owner', 'member'])
);

CREATE POLICY basejump_account_user_update_policy
ON basejump.account_user
FOR UPDATE USING (
    basejump.has_role_on_account(account_id, auth.uid(), ARRAY['owner'])
);

CREATE POLICY basejump_account_user_insert_policy
ON basejump.account_user
FOR INSERT WITH CHECK (
    basejump.has_role_on_account(account_id, auth.uid(), ARRAY['owner'])
);

CREATE POLICY basejump_account_user_delete_policy
ON basejump.account_user
FOR DELETE USING (
    basejump.has_role_on_account(account_id, auth.uid(), ARRAY['owner'])
);

-- ---------------------------------------------------------------------
-- Final Grants
-- ---------------------------------------------------------------------
GRANT USAGE ON SCHEMA basejump TO authenticated, service_role;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA basejump TO authenticated, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA basejump TO authenticated, service_role;

-- =====================================================================
-- End of basejump-accounts.sql
-- =====================================================================
