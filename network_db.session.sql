-- @block
CREATE TABLE
    auth (
        username VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
    );

-- @block
CREATE TABLE
    trap_data (
        time TIMESTAMP NOT NULL,
        ip VARCHAR(255) NOT NULL,
        event TEXT NOT NULL
    );

-- @block
DELETE FROM auth
WHERE
    username = 'user';