-- The seeded admin has a publicly documented password; admins now come from OIDC.
-- Its shared address books stay; the first OIDC admin takes them over.
DELETE FROM ab_peer WHERE ab IN (SELECT guid FROM ab WHERE owner = '\x018f2556230179eb91a2cffe5ced4236' AND personal = 1);
DELETE FROM ab_tag WHERE ab IN (SELECT guid FROM ab WHERE owner = '\x018f2556230179eb91a2cffe5ced4236' AND personal = 1);
DELETE FROM ab_rule WHERE ab IN (SELECT guid FROM ab WHERE owner = '\x018f2556230179eb91a2cffe5ced4236' AND personal = 1);
DELETE FROM ab WHERE owner = '\x018f2556230179eb91a2cffe5ced4236' AND personal = 1;
DELETE FROM ab_rule WHERE "user" = '\x018f2556230179eb91a2cffe5ced4236';
DELETE FROM ab_legacy WHERE user_guid = '\x018f2556230179eb91a2cffe5ced4236';
DELETE FROM session WHERE "user" = '\x018f2556230179eb91a2cffe5ced4236';
DELETE FROM user_data WHERE "user" = '\x018f2556230179eb91a2cffe5ced4236';
DELETE FROM user_third_auth WHERE "user" = '\x018f2556230179eb91a2cffe5ced4236';
DELETE FROM audit_alarm WHERE "user" = '\x018f2556230179eb91a2cffe5ced4236';
UPDATE peer SET "user" = NULL WHERE "user" = '\x018f2556230179eb91a2cffe5ced4236';
DELETE FROM "user" WHERE guid = '\x018f2556230179eb91a2cffe5ced4236';
