

ALTER TABLE users
    ADD column provider varchar(255) default 'EMAIL',
    ADD column provider_id varchar(255)