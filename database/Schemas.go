package database

func GetTableQueries() []string {
	return []string{

		`CREATE TABLE IF NOT EXISTS users (
			Created         TEXT,
			Name            TEXT NOT NULL,
			Email           TEXT NOT NULL,
			Phone_number    TEXT,
			Password        TEXT ,
			Additionaldata  TEXT,
			Status          TEXT,
			Userid          SERIAL PRIMARY KEY
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
			Userid           INT REFERENCES users(userid)

		)`,
	}
}
