-- Login is OIDC-only; nothing reads or writes passwords any more.
ALTER TABLE "user" DROP COLUMN password;
