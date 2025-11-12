-- User demo1
-- password: welcome
insert into "users" 
    (user_id, name, email, ctime, mtime) values 
    ('demo1', 'demo1', 'demo1@example.com', now(), now());
insert into "password_auth" 
    (user_serial_id, pwd, pwd_salt, ctime, mtime) values 
    (
        (select serial_id from users where user_id = 'demo1' limit 1),
        '#02#$argon2id$v=19$m=19456,t=2,p=1$X0rT4G7dR4iwt5GvVm8mbg$6/Yrgluppw4SFrszzByiXd04cl2DHmlb1XCHhuDMBJM',
        '5f4ad3e0-6edd-4788-b0b7-91af566f266e',
        now(),
        now()
    );
