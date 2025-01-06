-- --------------------------------------
-- UUID extension
-- --------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- --------------------------------------
-- Table structure for otp
-- --------------------------------------
CREATE TABLE "otp" (
    "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
    "user_id" uuid NOT NULL,
    "otp_code" VARCHAR(6) NOT NULL,
    "otp_type" VARCHAR(50) NOT NULL,
    "expires_at" timestamptz(6) NOT NULL,
    "used_at" timestamptz(6),
    "created_at" timestamptz(6) NOT NULL DEFAULT now(),
    "updated_at" timestamptz(6) DEFAULT now(),
    "deleted_at" timestamptz(6),
    PRIMARY KEY ("id")
);

-- --------------------------------------
-- Owner for otp
-- --------------------------------------
ALTER TABLE
    "otp" OWNER TO "postgres";

-- --------------------------------------
-- Refference for otp
-- --------------------------------------
ALTER TABLE
    "otp"
ADD
    CONSTRAINT "fk_otp_user_id" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;

-- --------------------------------------
-- Index for otp
-- --------------------------------------
CREATE INDEX "idx_otp_created_at" ON "otp" ("created_at");

CREATE INDEX "idx_otp_updated_at" ON "otp" ("updated_at");

CREATE INDEX "idx_otp_deleted_at" ON "otp" ("deleted_at");

CREATE INDEX "idx_otp_user_id" ON "otp" ("user_id");

CREATE INDEX "idx_otp_otp_type" ON "otp" ("otp_type");

CREATE INDEX "idx_otp_otp_code" ON "otp" ("otp_code");

CREATE INDEX "idx_otp_expires_at" ON "otp" ("expires_at");

CREATE INDEX "idx_otp_used_at" ON "otp" ("used_at");

-- index for non deleted otp
CREATE INDEX "idx_non_deleted_otp" ON "otp" ("user_id", "otp_code")
WHERE
    "deleted_at" IS NULL;