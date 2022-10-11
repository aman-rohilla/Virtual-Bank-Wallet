CREATE TABLE users(
    uid INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) NOT NULL,
    email VARCHAR(50) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    balance REAL DEFAULT 0
);

CREATE TABLE transactions(
    tid INTEGER PRIMARY KEY AUTOINCREMENT,
    uid INTEGER NOT NULL,
    type VARCHAR(6) NOT NULL, -- DEBIT, CREDIT
    amount REAL NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- CREATE TRIGGER users_tgr 
--    BEFORE
-- UPDATE ON
-- users
-- BEGIN
--     SELECT
--         CASE
--     	WHEN NEW.balance < 0 THEN
--    	      RAISE (FAIL,'Not Enough Balance')
--     END;
-- END;

-- UPDATE users SET balance = ((SELECT balance FROM users WHERE uid = 1) - 10) WHERE uid = 1; 
-- INSERT INTO transactions(uid, type, amount) VALUES(1, '', 5000);