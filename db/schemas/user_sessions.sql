-- --------------------------------------
-- UUID extension
-- --------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- --------------------------------------
-- Table structure for user_sessions
-- --------------------------------------
CREATE TABLE "user_sessions" (
    "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
    "session_id" uuid NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
    "user_id" uuid NOT NULL,
    "alias" uuid NOT NULL UNIQUE,
    "access_uuid" uuid NOT NULL UNIQUE,
    "refresh_uuid" uuid NOT NULL UNIQUE,
    "user_agent" BYTEA NOT NULL,
    "user_agent_hash" TEXT NOT NULL,
    "ip_address" BYTEA NOT NULL,
    "ip_address_hash" TEXT NOT NULL,
    "expires_at" timestamptz(6) NOT NULL,
    "revoked_at" timestamptz(6),
    "created_at" timestamptz(6) NOT NULL DEFAULT now(),
    "updated_at" timestamptz(6) DEFAULT now(),
    "deleted_at" timestamptz(6),
    PRIMARY KEY ("id")
);

-- --------------------------------------
-- Table owner
-- --------------------------------------
ALTER TABLE
    "user_sessions" OWNER TO "postgres";

-- --------------------------------------
-- Composite unique index
-- --------------------------------------
CREATE UNIQUE INDEX "idx_usrssn_user_agent_ip" ON "user_sessions" USING btree ("user_agent_hash", "ip_address_hash");

-- --------------------------------------
-- Foreign key constraints
-- --------------------------------------
ALTER TABLE
    "user_sessions"
ADD
    CONSTRAINT "fk_usrssn_user_id" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;

-- --------------------------------------
-- Indexes for performance
-- --------------------------------------
CREATE INDEX "idx_usrssn_created_at" ON "user_sessions" USING btree ("created_at");

CREATE INDEX "idx_usrssn_updated_at" ON "user_sessions" USING btree ("updated_at");

CREATE INDEX "idx_usrssn_deleted_at" ON "user_sessions" USING btree ("deleted_at");

CREATE INDEX "idx_usrssn_expires_at" ON "user_sessions" USING btree ("expires_at");

CREATE INDEX "idx_usrssn_revoked_at" ON "user_sessions" USING btree ("revoked_at");

CREATE INDEX "idx_usrssn_user_id" ON "user_sessions" USING btree ("user_id");

CREATE INDEX "idx_usrssn_session_id" ON "user_sessions" USING btree ("session_id");

CREATE INDEX "idx_usrssn_alias" ON "user_sessions" USING btree ("alias");

CREATE INDEX "idx_usrssn_access_uuid" ON "user_sessions" USING btree ("access_uuid");

CREATE INDEX "idx_usrssn_refresh_uuid" ON "user_sessions" USING btree ("refresh_uuid");

CREATE INDEX "idx_usrssn_user_agent_hash" ON "user_sessions" USING btree ("user_agent_hash");

CREATE INDEX "idx_usrssn_ip_address_hash" ON "user_sessions" USING btree ("ip_address_hash");

--index for non deleted sessions
CREATE INDEX "idx_usrssn_not_deleted" ON "user_sessions" USING btree ("deleted_at")
WHERE
    "deleted_at" IS NULL;