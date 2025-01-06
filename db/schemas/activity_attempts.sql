-- --------------------------------------
-- UUID extension
-- --------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- --------------------------------------
-- Table structure for activity_attempts
-- --------------------------------------
CREATE TABLE "activity_attempts" (
    "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
    "user_id" uuid NOT NULL,
    "activity" VARCHAR(255) NOT NULL,
    "attempt_time" timestamptz(6) NOT NULL DEFAULT now(),
    "success" BOOLEAN NOT NULL,
    "description" TEXT,
    "resolved_at" timestamptz(6),
    "created_at" timestamptz(6) NOT NULL DEFAULT now(),
    "updated_at" timestamptz(6) DEFAULT now(),
    "deleted_at" timestamptz(6),
    PRIMARY KEY ("id")
);

-- --------------------------------------
-- Owner for activity_attempts
-- --------------------------------------
ALTER TABLE
    "activity_attempts" OWNER TO "postgres";

-- --------------------------------------
-- Refference for activity_attempts
-- --------------------------------------
ALTER TABLE
    "activity_attempts"
ADD
    CONSTRAINT "fk_actemp_user_id" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;

-- --------------------------------------
-- Index for activity_attempts
-- --------------------------------------
CREATE INDEX "idx_actemp_user_id" ON "activity_attempts" ("user_id");

CREATE INDEX "idx_actemp_activity" ON "activity_attempts" ("activity");

CREATE INDEX "idx_actemp_attempt_time" ON "activity_attempts" ("attempt_time");

CREATE INDEX "idx_actemp_success" ON "activity_attempts" ("success");

CREATE INDEX "idx_actemp_resolved_at" ON "activity_attempts" ("resolved_at");

CREATE INDEX "idx_actemp_created_at" ON "activity_attempts" ("created_at");

CREATE INDEX "idx_actemp_updated_at" ON "activity_attempts" ("updated_at");

CREATE INDEX "idx_actemp_deleted_at" ON "activity_attempts" ("deleted_at");

-- index for non deleted activity logs
CREATE INDEX "idx_actemp_active_logs" ON "activity_attempts" ("user_id", "activity")
WHERE
    "deleted_at" IS NULL;