CREATE TABLE audit_action_categories (
  code varchar(50) PRIMARY KEY,
  title varchar(100) NOT NULL,
  description text NOT NULL,
  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  is_deleted boolean DEFAULT FALSE
);

CREATE TABLE audit_action_types (
  code varchar(50) PRIMARY KEY,
  title varchar(100) NOT NULL,
  description text NOT NULL,
  category_code varchar(50) NOT NULL,
  is_deleted boolean DEFAULT FALSE,
  created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (category_code) REFERENCES audit_action_categories(code)
);


CREATE TABLE audit_logs (
  id UUID PRIMARY KEY,
  actor_id UUID NOT NULL,
  actor_type varchar(50) NOT NULL,
  target_id UUID,
  target_type varchar(50) Not NULL,
  action_type_code varchar(50) NOT NULL,
action_category_code varchar(50) NOT NULL,
  impersonated_user_id UUID,
  previous_data JSONB,
  new_data JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    source_device VARCHAR(255),
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
 
  FOREIGN KEY (action_type_code) REFERENCES audit_action_types(code)
);

CREATE INDEX idx_audit_actor ON audit_logs(actor_type, actor_id);
CREATE INDEX idx_audit_target ON audit_logs(target_type, target_id);
CREATE INDEX idx_audit_action ON audit_logs(action_type_code);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_impersonation ON audit_logs(impersonated_user_id);

