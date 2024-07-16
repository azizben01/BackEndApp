package main

import (
	"ben/benaziz/BackEndApp/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	router := gin.Default()
	database.ConnectDatabase()
	router.POST("/user", CreateUser)
	router.POST("/transaction", CreateTransaction)
	router.GET("/users/:username", GetUser)
	router.POST("/login", LoginUser)
	router.GET("/transactions", GetTransaction)
	router.DELETE("/transactions/:transactionid", DeleteTransaction)
	db := &database.Database{DB: database.DB} // db points to database.Database  which will store database.DB into its variable DB .... /:transactionid
	db.InitDatabase()

	router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{
			"message": "Your server is running well !!",
		})
	})
	err := router.Run(":1010")
	if err != nil {
		panic(err)
	}
}

type User struct {
	Username       string `json:"username"`
	Email          string `json:"email"`
	Phone_number   string `json:"phone_number"`
	Password       string `json:"password"`
	Additionaldata string `json:"additionaldata"`
	Status         string `json:"status"`
}

func CreateUser(ctx *gin.Context) {
	body := User{}
	data, err := ctx.GetRawData()
	if err != nil {
		ctx.AbortWithStatusJSON(400, "User is not defined")
		return
	}
	err = json.Unmarshal(data, &body)
	if err != nil {
		ctx.AbortWithStatusJSON(400, "Bad Input")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	body.Password = string(hashedPassword)

	_, err = database.DB.Exec("insert into users(username, email, phone_number, password, additionaldata, status) values ($1,$2,$3,$4,$5,$6)", body.Username, body.Email, body.Phone_number, body.Password, body.Additionaldata, body.Status)
	if err != nil {
		fmt.Println(err)
		// fmt.Println("HELLO HERE")
		ctx.AbortWithStatusJSON(400, "Could not create a new user")

	} else {
		ctx.JSON(http.StatusOK, "New user successfully created")
	}

	//defer database.DB.Close()

}

type Transaction struct {
	Username         string `json:"username"`
	Amount           int    `json:"amount"`
	Currency         string `json:"currency"`
	Sender_phone     string `json:"sender_phone"`
	Recipient_phone  string `json:"recipient_phone"`
	Recipient_name   string `json:"recipient_name"`
	New_balance      string `json:"new_balance"`
	Transaction_type string `json:"transaction_type"`
	Additionaldata   string `json:"additionaldata"`
	Created          string `json:"created"`
	Transactionid    int    `json:"transactionid"`
}

func CreateTransaction(c *gin.Context) {
	body := Transaction{}
	data, err := c.GetRawData()
	if err != nil {
		c.AbortWithStatusJSON(400, "Transaction failed")
	}
	err = json.Unmarshal(data, &body)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(400, "Bad Input")

		return
	}
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	body.Created = currentTime

	_, err = database.DB.Exec("INSERT INTO transactions (username, amount, currency, sender_phone, recipient_phone, recipient_name, new_balance, transaction_type, additionaldata, created) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", body.Username, body.Amount, body.Currency, body.Sender_phone, body.Recipient_phone, body.Recipient_name, body.New_balance, body.Transaction_type, body.Additionaldata, body.Created)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(400, "Failed to create transaction")
	} else {
		c.JSON(http.StatusOK, "Transaction successful")
	}
}

func GetUser(c *gin.Context) {
	// Extract the userid parameter from the URL
	username := c.Param("username")

	// Query the database to get user info based on userid
	var userinfo User
	err := database.DB.QueryRow("SELECT * FROM users WHERE username = $1", username).
		Scan(&userinfo.Username, &userinfo.Email, &userinfo.Phone_number, &userinfo.Password, &userinfo.Additionaldata, &userinfo.Status)
	fmt.Println("username", userinfo.Username)
	if err != nil {
		// If user not found, return 404 Not Found response
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Return the user info as JSON
	c.JSON(http.StatusOK, userinfo)
}

func LoginUser(c *gin.Context) {
	var reqUser User
	if err := c.ShouldBindJSON(&reqUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedUser User
	err := database.DB.QueryRow("SELECT username, email, phone_number, password, additionaldata, status FROM users WHERE email = $1", reqUser.Email).
		Scan(&storedUser.Username, &storedUser.Email, &storedUser.Phone_number, &storedUser.Password, &storedUser.Additionaldata, &storedUser.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(reqUser.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Include user details in the response
	c.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"username":     storedUser.Username,
		"email":        storedUser.Email,
		"phone_number": storedUser.Phone_number,
	})
}

// func GetTransaction(c *gin.Context) {
// 	transactionid := c.Param("transactionid")
// 	var trans Transaction
// 	err := database.DB.QueryRow("SELECT * FROM transactions  WHERE transactionid = $1", transactionid).
// 		Scan(&trans.Amount, &trans.Currency, &trans.Sender_phone, &trans.Recipient_phone, &trans.Recipient_name, &trans.New_balance, &trans.Transaction_type, &trans.Additionaldata, &trans.Transactionid, &trans.Userid)
// 	if err != nil {
// 		fmt.Println(err)
// 		c.JSON(http.StatusNotFound, gin.H{"error": "Transaction not found"})
// 		return

// 	}
// 	c.JSON(http.StatusOK, trans)
// }

func GetTransaction(c *gin.Context) {
	var transactions []Transaction
	rows, err := database.DB.Query("SELECT * FROM transactions")
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve transactions"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var trans Transaction //
		err := rows.Scan(&trans.Amount, &trans.Currency, &trans.Sender_phone, &trans.Recipient_phone, &trans.Recipient_name, &trans.New_balance, &trans.Transaction_type, &trans.Additionaldata, &trans.Created, &trans.Transactionid, &trans.Username)
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing transaction data"})
			return
		}
		transactions = append(transactions, trans)
	}

	c.JSON(http.StatusOK, transactions)
}

func DeleteTransaction(c *gin.Context) {
	transactionid := c.Param("transactionid")

	_, err := database.DB.Exec("DELETE FROM transactions WHERE transactionid = $1", transactionid)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete transaction"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Transaction deleted successfully"})
}
