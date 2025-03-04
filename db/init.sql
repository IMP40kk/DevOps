CREATE USER ${DB_REPL_USER} WITH REPLICATION ENCRYPTED PASSWORD '${DB_REPL_PASSWORD}';

\connect ${DB_DATABASE};

CREATE TABLE IF NOT EXISTS emails (
    ID SERIAL PRIMARY KEY,
    email VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS phone_numbers (
    ID SERIAL PRIMARY KEY,
    phone_number VARCHAR(30) NOT NULL
);

INSERT INTO emails (email) VALUES
    ('user1@example.com'),
    ('user2@example.com');

INSERT INTO phone_numbers (phone_number) VALUES
    ('88005553535'),
    ('+78005553536');