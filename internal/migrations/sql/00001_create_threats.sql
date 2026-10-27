-- +goose Up
CREATE TABLE threats (
    md5 text COLLATE "C",
    name text NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    type text COLLATE "C" NOT NULL,
    severity text COLLATE "C" NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT threats_pkey PRIMARY KEY (md5),

    CONSTRAINT threats_md5_format
        CHECK (md5 ~ '^[0-9a-f]{32}$'),

    CONSTRAINT threats_name_length
        CHECK (char_length(name) BETWEEN 1 AND 200),

    CONSTRAINT threats_description_length
        CHECK (char_length(description) <= 4096),

    CONSTRAINT threats_type_check
        CHECK (type IN (
            'trojan',
            'ransomware',
            'spyware',
            'adware',
            'worm',
            'other'
        )),

    CONSTRAINT threats_severity_check
        CHECK (severity IN (
            'low',
            'medium',
            'high',
            'critical'
        ))
);