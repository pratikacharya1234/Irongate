-- IronGate Database Initialization
-- Run this before Alembic migrations for fresh installs.

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- Trigram for fuzzy search

-- Create application role with limited privileges
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'irongate_app') THEN
        CREATE ROLE irongate_app WITH LOGIN PASSWORD 'changeme';
    END IF;
END
$$;

-- Grant privileges
GRANT CONNECT ON DATABASE irongate TO irongate_app;
GRANT USAGE ON SCHEMA public TO agentshield_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agentshield_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO agentshield_app;

-- Create indexes that help with common queries (beyond what SQLAlchemy creates)
-- These will be created after Alembic runs the initial migration

-- Partitioning setup for threat_events (high volume table)
-- NOTE: Uncomment and adapt for production when data volume warrants it
-- CREATE TABLE IF NOT EXISTS threat_events_y2026m01 PARTITION OF threat_events
--     FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
