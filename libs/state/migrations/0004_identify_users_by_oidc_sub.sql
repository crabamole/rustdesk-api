-- Users are identified by their OIDC subject; name and email are display data.
ALTER TABLE "user" ADD COLUMN oidc_sub varchar(255);
CREATE UNIQUE INDEX index_user_oidc_sub ON "user" (oidc_sub);
DROP INDEX IF EXISTS index_user_name;
DROP INDEX IF EXISTS index_user_email;
CREATE INDEX index_user_name ON "user" (name);
CREATE INDEX index_user_email ON "user" (email);
UPDATE "user" SET email = NULL WHERE email = 'tobefilled@example;org';
