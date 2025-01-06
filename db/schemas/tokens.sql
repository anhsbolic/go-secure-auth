-- --------------------------------------
-- UUID extension
-- --------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- --------------------------------------
-- Table structure for tokens
-- --------------------------------------
CREATE TABLE "tokens" (
    "id" uuid NOT NULL DEFAULT uuid_generate_v4(),
    "user_id" uuid NOT NULL,
    "token_hash" TEXT NOT NULL UNIQUE,
    "token_type" VARCHAR(50) NOT NULL,
    "expires_at" timestamptz(6) NOT NULL,
    "used_at" timestamptz(6),
    "revoked_at" timestamptz(6),
    "created_at" timestamptz(6) NOT NULL DEFAULT now(),
    "updated_at" timestamptz(6) DEFAULT now(),
    "deleted_at" timestamptz(6),
    PRIMARY KEY ("id")
);

-- --------------------------------------
-- Owner for tokens
-- --------------------------------------
ALTER TABLE
    "tokens" OWNER TO "postgres";

-- --------------------------------------
-- Refference for tokens
-- --------------------------------------
ALTER TABLE
    "tokens"
ADD
    CONSTRAINT "fk_tkn_user_id" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;

-- --------------------------------------
-- Index for tokens
-- --------------------------------------
CREATE INDEX "idx_tkn_created_at" ON "tokens" ("created_at");

CREATE INDEX "idx_tkn_updated_at" ON "tokens" ("updated_at");

CREATE INDEX "idx_tkn_deleted_at" ON "tokens" ("deleted_at");

CREATE INDEX "idx_tkn_expires_at" ON "tokens" ("expires_at");

CREATE INDEX "idx_tkn_used_at" ON "tokens" ("used_at");

CREATE INDEX "idx_tkn_revoked_at" ON "tokens" ("revoked_at");

CREATE INDEX "idx_tkn_user_id" ON "tokens" ("user_id");

CREATE INDEX "idx_tkn_token_type" ON "tokens" ("token_type");

-- index for non deleted tokens
CREATE INDEX "idx_non_deleted_tokens" ON "tokens" ("id")
WHERE "deleted_at" IS NULL;