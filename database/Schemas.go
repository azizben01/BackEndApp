package database

func GetTableQueries() []string {
	return []string{

		`CREATE TABLE IF NOT EXISTS users (
			Username        TEXT PRIMARY KEY,
			Email           TEXT NOT NULL,
			Phone_number    TEXT,
			Password        TEXT ,
			Additionaldata  TEXT,
			Status          TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS transactions (
		    Username         TEXT REFERENCES users(Username),
			Amount           INT,
			Currency         TEXT,
			Sender_phone     TEXT,
			Recipient_phone  TEXT,
			Recipient_name   TEXT,
			New_balance      TEXT,
			Transaction_type TEXT,
			Additionaldata   TEXT,
			Created          TEXT,
			Transactionid    SERIAL PRIMARY KEY
		)`,
	}
}
