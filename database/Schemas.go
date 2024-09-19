package database

func GetTableQueries() []string {
	return []string{
		// make a full name for the employee
		`CREATE TABLE IF NOT EXISTS employees (
			username           TEXT PRIMARY KEY, 
			employeefullname   TEXT,
			email              TEXT NOT NULL,
			phonenumber        TEXT NOT NULL,
			password           TEXT NOT NULL,
			position		   TEXT NOT NULL,
			created			   TEXT NOT NULL,
			additionaldata     TEXT,
			status             TEXT,
			resettoken         TEXT,
	        resettokenexpiry   TIMESTAMP WITH TIME ZONE,
			failed_attempts  INT DEFAULT 0,
    		lockout_until    TIMESTAMP WITH TIME ZONE  
		)`,

		`CREATE TABLE IF NOT EXISTS transactions (
		    transactionid    SERIAL PRIMARY KEY,
		    username         TEXT NOT NULL,
			amount           INT  NOT NULL,
			currency         TEXT,
			senderphone      TEXT NOT NULL, 
			recipientphone   TEXT NOT NULL,
			recipientname    TEXT NOT NULL,
			newbalance       TEXT,
			transactiontype  TEXT,
			additionaldata   TEXT,
			created          TEXT,
			is_deleted       BOOLEAN DEFAULT FALSE,
			FOREIGN KEY (username) REFERENCES employees (username)
			ON DELETE CASCADE
			ON UPDATE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS admin (
			adminname  		 TEXT PRIMARY KEY,
			fullname         TEXT NOT NULL,
			phonenumber		 INT  NOT NULL,
			password   		 TEXT NOT NULL,
			email	   		 TEXT NOT NULL,
			status     		 TEXT,
			resettoken         TEXT,
	        resettokenexpiry   TIMESTAMP WITH TIME ZONE,
			failed_attempts  INT DEFAULT 0,  -- Track failed login attempts
            lockout_until    TIMESTAMP WITH TIME ZONE  -- Track lockout expiration time
		)`,

		`CREATE TABLE IF NOT EXISTS admintransactions (
			adminTransactionid SERIAL PRIMARY KEY,
			adminname TEXT NOT NULL,
			amount INT NOT NULL,
			currency TEXT NOT NULL,
			adminphone TEXT NOT NULL,
			username TEXT NOT NULL,
			employeephone TEXT NOT NULL,
			newbalance TEXT,
			transactiontype TEXT NOT NULL,
			additionaldata TEXT,
			created TEXT,
			is_deleted BOOLEAN DEFAULT FALSE,
			FOREIGN KEY (adminname) REFERENCES admin (adminname)
			ON DELETE CASCADE
			ON UPDATE CASCADE,
			FOREIGN KEY (username) REFERENCES employees (username)
			ON DELETE CASCADE
			ON UPDATE CASCADE
);`,

		`CREATE TABLE IF NOT EXISTS reports (
			report_id              SERIAL PRIMARY KEY,
			title                  TEXT NOT NULL,
			description            TEXT,
    		createdby              TEXT NOT NULL,
    		period                 TEXT NOT NULL,
    		numberofemployees      INT,
    		numberoftransactions   INT,
    		highesttransaction     INT,
    		lowesttransaction      INT,
    		totalamounttransferred INT,
    		created_at             TEXT,
    		additionaldata         TEXT
		)`,
	}

}
