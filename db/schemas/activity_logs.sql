-- --------------------------------------
-- UUID extension
-- --------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- --------------------------------------
-- Table structure for activity_logs
-- --------------------------------------
CREATE TABLE "activity_logs" (
    "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
    "user_id" uuid NOT NULL,
    "user_agent" BYTEA NOT NULL,
    "user_agent_hash" TEXT NOT NULL,
    "ip_address" BYTEA NOT NULL,
    "ip_address_hash" TEXT NOT NULL,
    "activity" VARCHAR(255) NOT NULL,
    "activity_time" timestamptz(6) NOT NULL DEFAULT now(),
    "description" TEXT,
    "created_at" timestamptz(6) NOT NULL DEFAULT now(),
    "updated_at" timestamptz(6) DEFAULT now(),
    "deleted_at" timestamptz(6),
    PRIMARY KEY ("id")
);

-- --------------------------------------
-- Owner for activity_logs
-- --------------------------------------
ALTER TABLE
    "activity_logs" OWNER TO "postgres";

-- --------------------------------------
-- Refference for activity_logs
-- --------------------------------------
ALTER TABLE
    "activity_logs"
ADD
    CONSTRAINT "fk_alog_user_id" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;

-- --------------------------------------
-- Index for activity_logs
-- --------------------------------------
CREATE INDEX "idx_alog_user_id" ON "activity_logs" ("user_id");

CREATE INDEX "idx_alog_user_agent_hash" ON "activity_logs" ("user_agent_hash");

CREATE INDEX "idx_alog_ip_address_hash" ON "activity_logs" ("ip_address_hash");

CREATE INDEX "idx_alog_activity" ON "activity_logs" ("activity");

CREATE INDEX "idx_alog_activity_time" ON "activity_logs" ("activity_time");

CREATE INDEX "idx_alog_created_at" ON "activity_logs" ("created_at");

CREATE INDEX "idx_alog_updated_at" ON "activity_logs" ("updated_at");

CREATE INDEX "idx_alog_deleted_at" ON "activity_logs" ("deleted_at");

-- index for non deleted activity logs
CREATE INDEX "idx_alog_active_logs" ON "activity_logs" ("user_id", "activity")
WHERE
    "deleted_at" IS NULL;