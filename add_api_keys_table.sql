-- Run in Supabase SQL Editor
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(100) NOT NULL,
    key_prefix VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
