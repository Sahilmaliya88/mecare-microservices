CREATE TABLE login_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id       VARCHAR(255) NOT NULL,
    token_version   VARCHAR(255) NOT NULL,
    device_type     VARCHAR(100) NOT NULL,
    browser         VARCHAR(100) NOT NULL,
    os              VARCHAR(100) NOT NULL,
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    created_at      TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at    TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    actual_session_id UUID REFERENCES login_sessions(id) ON DELETE SET NULL,
    impersonated_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    is_active       BOOLEAN DEFAULT TRUE
);

CREATE UNIQUE INDEX idx_unique_user_device ON login_sessions (user_id, device_id) WHERE is_active = TRUE;
CREATE INDEX idx_login_sessions_user_id ON login_sessions (user_id);