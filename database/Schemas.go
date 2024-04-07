package database

func GetTableQueries() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS users (
			Created         TEXT,
			Name           TEXT,
			Email          TEXT,
			Phone_number   TEXT,
			Additionaldata  TEXT,
			Status         TEXT,
			Userid         SERIAL PRIMARY KEY
		)`,
		`CREATE TABLE IF NOT EXISTS transactions (
			Amount           INT,
			Currency         TEXT,
			Sender_number    TEXT,
			Recipient_number TEXT,
			Recipient_name   TEXT,
			New_balance      TEXT,
			Transaction_type TEXT,
			Additionaldata   TEXT,
			Transactionid    SERIAL PRIMARY KEY,
			Userid           INT REFERENCES users(userid)

		)`,
	}
}
