-- =====================================================================
-- Migration: Basejump Setup (Supabase-safe version)
-- Description:
--   Creates the 'basejump' schema and functions compatible with Supabase.
--   Removes dependency on gen_random_bytes() to avoid pgcrypto issues.
-- =====================================================================

-- Create schema if missing
CREATE SCHEMA IF NOT EXISTS basejump;

-- =====================================================================
-- Function: basejump.generate_token(length)
-- Generates a random token string safely (works even if pgcrypto disabled)
-- =====================================================================

CREATE OR REPLACE FUNCTION basejump.generate_token(length int)
RETURNS text AS
$$
-- Fallback generator using md5(random())
-- Each call concatenates two md5 hashes to increase randomness
SELECT substring(
  replace(
    encode(
      decode(md5(random()::text || clock_timestamp()::text || md5(random()::text)), 'hex'),
      'base64'
    ),
    '=', ''
  )
  FROM 1 FOR length
);
$$ LANGUAGE sql STABLE;

-- =====================================================================
-- Function: basejump.lower_trim(text)
-- Converts text to lowercase and trims spaces.
-- =====================================================================

CREATE OR REPLACE FUNCTION basejump.lower_trim(input text)
RETURNS text AS
$$
SELECT lower(trim(input));
$$ LANGUAGE sql IMMUTABLE;

-- =====================================================================
-- Function: basejump.timestamp_now()
-- Returns the current UTC timestamp.
-- =====================================================================

CREATE OR REPLACE FUNCTION basejump.timestamp_now()
RETURNS timestamptz AS
$$
SELECT now() AT TIME ZONE 'utc';
$$ LANGUAGE sql STABLE;

-- =====================================================================
-- Table: basejump.invitations
-- Example table using generate_token for secure invites.
-- =====================================================================

CREATE TABLE IF NOT EXISTS basejump.invitations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL,
    token text NOT NULL DEFAULT basejump.generate_token(24),
    created_at timestamptz NOT NULL DEFAULT basejump.timestamp_now(),
    accepted boolean DEFAULT false
);

-- =====================================================================
-- Done
-- =====================================================================
