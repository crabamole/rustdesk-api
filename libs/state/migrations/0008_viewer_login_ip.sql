-- Where the viewer last logged in from. One row per machine and user: another user's login
-- with the same ID and uuid adds its own row instead of taking this one over.
ALTER TABLE viewer_device ADD COLUMN login_ip text NOT NULL DEFAULT '';
ALTER TABLE viewer_device DROP CONSTRAINT viewer_device_pkey;
ALTER TABLE viewer_device ADD PRIMARY KEY (id, uuid, "user");
