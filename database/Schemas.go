package database

func GetTableQueries() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS users (
			Created        string
			Name           string
			Email          string
			Phone_number   string
			Additionaldata json.RawMessage
			Status         string
			Userid         int
		)`,
		`CREATE TABLE IF NOT EXISTS transactions (
			Amount           int
			Currency         string
			Sender_number    string
			Recipient_number string
			Recipient_name   string
			New_balance      string
			Transaction_type string
			Additionaldata   json.RawMessage
			Transactionid    int
			Userid           int

		)`,
	}
}
