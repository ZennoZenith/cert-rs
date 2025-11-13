-- User demo1
-- password: welcome
INSERT INTO "users" 
    (user_id, name, email, ctime, mtime) 
VALUES 
    ('demo1', 'demo1', 'demo1@example.com', datetime('now'), datetime('now'));

INSERT INTO "password_auth" 
    (user_serial_id, pwd, pwd_salt, ctime, mtime) 
VALUES 
    (
        (SELECT serial_id FROM users WHERE user_id = 'demo1' LIMIT 1),
        '#02#$argon2id$v=19$m=19456,t=2,p=1$X0rT4G7dR4iwt5GvVm8mbg$6/Yrgluppw4SFrszzByiXd04cl2DHmlb1XCHhuDMBJM',
        CAST('5f4ad3e0-6edd-4788-b0b7-91af566f266e' as BLOB),
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    );
