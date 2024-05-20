package database

func GetTableQueries() []string {
	return []string{

		`CREATE TABLE IF NOT EXISTS users (
			UserID         SERIAL PRIMARY KEY,
			Created         TEXT,
			Name            TEXT NOT NULL,
			Email           TEXT NOT NULL,
			Phone_number    TEXT,
			Password        TEXT ,
			Additionaldata  TEXT,
			Status          TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS transactions (
			Amount           INT,
			Currency         TEXT,
			Sender_phone     TEXT,
			Recipient_phone  TEXT,
			Recipient_name   TEXT,
			New_balance      TEXT,
			Transaction_type TEXT,
			Additionaldata   TEXT,
			Transactionid    SERIAL PRIMARY KEY,
			UserID           INT REFERENCES users(userID)

		)`,
	}
}
