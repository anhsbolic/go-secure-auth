-- --------------------------------------
-- UUID extension
-- --------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- --------------------------------------
-- Table structure for users
-- --------------------------------------
CREATE TABLE "users" (
    "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
    "username" BYTEA NOT NULL,
    "username_hash" TEXT NOT NULL UNIQUE,
    "email" BYTEA NOT NULL,
    "email_hash" TEXT NOT NULL UNIQUE,
    "password_hash" TEXT NOT NULL,
    "role" VARCHAR(20) NOT NULL,
    "status" VARCHAR(20) NOT NULL DEFAULT 'inactive',
    "email_verified_at" timestamptz(6),
    "created_at" timestamptz(6) NOT NULL DEFAULT now(),
    "updated_at" timestamptz(6) DEFAULT now(),
    "deleted_at" timestamptz(6),
    PRIMARY KEY ("id")
);

-- --------------------------------------
-- Owner for users
-- --------------------------------------
ALTER TABLE
    "users" OWNER TO "postgres";

-- --------------------------------------
-- Index for users
-- --------------------------------------
CREATE INDEX "idx_usr_username_hash" ON "users" USING btree ("username_hash");

CREATE INDEX "idx_usr_email_hash" ON "users" USING btree ("email_hash");

CREATE INDEX "idx_usr_role" ON "users" USING btree ("role");

CREATE INDEX "idx_usr_status" ON "users" USING btree ("status");

CREATE INDEX "idx_usr_created_at" ON "users" USING btree ("created_at");

CREATE INDEX "idx_usr_updated_at" ON "users" USING btree ("updated_at");

CREATE INDEX "idx_usr_deleted_at" ON "users" USING btree ("deleted_at");

-- Partial index for active users
CREATE INDEX "idx_usr_active_users" ON "users" ("id")
WHERE "status" = 'active' AND "deleted_at" IS NULL;

-- Partial index for non-deleted users
CREATE INDEX "idx_usr_non_deleted_users" ON "users" ("id")
WHERE "deleted_at" IS NULL;