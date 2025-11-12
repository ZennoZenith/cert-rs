-- root user (at serial_id = 0)
insert into "users" 
    (serial_id, user_id, user_type_serial_id, name, email, ctime, mtime) values 
    (0, 'root', (select ut.serial_id from user_type ut where ut.typ = 'Sys'), 'root','root@example.com', now(), now());
