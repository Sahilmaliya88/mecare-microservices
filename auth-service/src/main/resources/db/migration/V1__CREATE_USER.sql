CREATE TABLE users
(
    id            UUID PRIMARY KEY  ,
    email         VARCHAR(255) UNIQUE,
    password      VARCHAR(255),
    is_active     BOOLEAN default true,
    created_at    TIMESTAMP WITHOUT TIME ZONE,
    updated_at    TIMESTAMP WITHOUT TIME ZONE,
    deleted_at    TIMESTAMP WITHOUT TIME ZONE,
    is_verified  BOOLEAN default false,
    verification_code VARCHAR(255),
    verification_code_expires_at TIMESTAMP WITHOUT TIME ZONE,
    password_reset_token VARCHAR(255),
    password_reset_token_expires_at TIMESTAMP WITHOUT TIME ZONE,
    token_version VARCHAR(255),
    role varchar(255) default 'USER'
);

-- Create index after table creation
CREATE INDEX idx_email ON users (email);
