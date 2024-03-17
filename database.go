package Database

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Database struct {
	db  *sql.DB
	ctx context.Context
}

func GetDatabase() Database {
	connStr := "user=benazizsangare dbname=swiftdb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Database connected")
	return Database{
		db:  db,
		ctx: context.Background(),
	}
}

func (database Database) InitDatabase() {
	tableQueries := []string{
		`CREATE TABLE IF NOT EXISTS users (
            userID TEXT NOT NULL PRIMARY KEY,
            created TEXT NOT NULL,
            name TEXT,
            email TEXT,
            phone_number TEXT,
            additionalData JSON,
            status TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS transactions (
            transactionID TEXT NOT NULL PRIMARY KEY,
            userid TEXT,
            amount INT,
            currency TEXT,
            sender_number TEXT,
            recipient_number TEXT,
            recipient_name TEXT,
            new_balance TEXT,
            transaction_type TEXT,
            additionalData JSON
        )`,
	}
	for _, query := range tableQueries {
		_, err := database.db.ExecContext(database.ctx, query)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (database Database) StartTransaction() *sql.Tx {
	tx, err := database.db.BeginTx(database.ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	return tx
}

func (database Database) Commit(tx *sql.Tx) error {
	return tx.Commit()
}

func (database Database) Rollback(tx *sql.Tx) {
	tx.Rollback()
}

func (database Database) Read(tx *sql.Tx, query string, args ...any) (ReadResult, error) {
	stmt, err := tx.PrepareContext(database.ctx, query)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	rows, qerr := stmt.QueryContext(database.ctx, args...)
	if qerr != nil {
		return ReadResult{}, qerr
	}
	return GetReadResult(rows), nil
}

func (database Database) Write(tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	stmt, err := tx.PrepareContext(database.ctx, query)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	return stmt.ExecContext(database.ctx, args...)
}

type ReadResult struct {
	data []map[string]any
}

func GetReadResult(rows *sql.Rows) ReadResult {
	columns, err := rows.Columns()
	if err != nil {
		log.Fatal(err)
	}

	columnLength := len(columns)
	result := []map[string]any{}
	for rows.Next() {
		columnValues := make([]any, columnLength)
		for i := range columnValues {
			columnValues[i] = new(string)
		}
		rowMap := map[string]any{}
		rows.Scan(columnValues...)
		for i := 0; i < columnLength; i++ {
			rowMap[columns[i]] = columnValues[i]
		}
		result = append(result, rowMap)
	}

	return ReadResult{
		data: result,
	}
}

func (result ReadResult) Get(index int) map[string]any {
	return result.data[index]
}

func (result ReadResult) GetAll() []map[string]any {
	return result.data
}

func (result ReadResult) GetString(index int, column string) string {
	val := result.data[index][strings.ToLower(column)]
	return reflect.ValueOf(val).Elem().String()
}

func (result ReadResult) GetInt(index int, column string) int {
	val := result.data[index][strings.ToLower(column)]
	intVal, err := strconv.Atoi(reflect.ValueOf(val).Elem().String())
	if err != nil {
		panic(err)
	}
	return intVal
}

func (result ReadResult) Size() int {
	return len(result.data)
}

func GetDatabaseID() string {
	id := uintToBase64String(rand.Uint64())
	log.Printf("Generated ID: %s", id)
	return id
}

func uintToBase64String(num uint64) string {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	i := num
	result := ""
	for ok := true; ok; ok = i != 0 {
		result += string(alphabet[(i % 64)])
		i = i / 64
	}
	return result
}

func GetDatabaseCreated() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func SliceToArgumentString(slice []string) string {
	result := ""
	for i := range slice {
		result += fmt.Sprintf("$%d,", i+1)
	}
	return result[:len(result)-1]
}

func GetAnySlice(slice []string) []any {
	result := []any{}
	for _, val := range slice {
		result = append(result, val)
	}
	return result
}
