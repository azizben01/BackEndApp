package database

func GetTableQueries() []string {
	return []string{

		`CREATE TABLE IF NOT EXISTS users (
			Username        TEXT PRIMARY KEY,
			Email           TEXT NOT NULL,
			Phonenumber    TEXT NOT NULL,
			Password        TEXT NOT NULL,
			Additionaldata  TEXT,
			Status          TEXT,
			Resettoken      TEXT,
	        Resettokenexpiry TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE TABLE IF NOT EXISTS transactions (
		    Transactionid    SERIAL PRIMARY KEY,
		    Username         TEXT NOT NULL,
			Amount           INT,
			Currency         TEXT,
			Senderphone     TEXT,
			Recipientphone  TEXT,
			Recipientname   TEXT,
			Newbalance      TEXT,
			Transactiontype TEXT,
			Additionaldata   TEXT,
			Created          TEXT,
			is_deleted       BOOLEAN DEFAULT FALSE,
			FOREIGN KEY (Username) REFERENCES users (Username)
			ON DELETE CASCADE
			ON UPDATE CASCADE
		)`,
	}
}
