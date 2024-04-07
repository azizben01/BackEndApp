package main

import (
	"ben/benaziz/BackEndApp/database"
	"encoding/json"
	"fmt"

	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	database.ConnectDatabase()
	router.POST("/user", CreateUser)
	router.POST("/transaction", CreateTransaction)
	router.GET("/users/:userid", GetUser)
	router.GET("/transactions/:transactionid", GetTransaction)
	router.DELETE("/transactions/:transactionid", DeleteTransaction)
	db := &database.Database{DB: database.DB}
	db.InitDatabase()

	router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{
			"message": "NOW YOU SEE!!",
		})
	})
	err := router.Run(":1010")
	if err != nil {
		panic(err)
	}

}

type User struct {
	Created        string          `json:"created"`
	Name           string          `json:"name"`
	Email          string          `json:"email"`
	Phone_number   string          `json:"phone_number"`
	Additionaldata json.RawMessage `json:"additionaldata"`
	Status         string          `json:"status"`
	Userid         int             `json:"userid"`
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
	_, err = database.DB.Exec("insert into users(created, name, email, phone_number, additionaldata, status) values ($1,$2,$3,$4,$5,$6)", body.Created, body.Name, body.Email, body.Phone_number, body.Additionaldata, body.Status)
	if err != nil {
		fmt.Println(err)
		fmt.Println("HELLO HERE")
		ctx.AbortWithStatusJSON(400, "Could not create a new user")

	} else {
		ctx.JSON(http.StatusOK, "New user successfully created")
	}
	defer database.DB.Close()

}

type Transaction struct {
	Amount           int             `json:"amount"`
	Currency         string          `json:"currency"`
	Sender_number    string          `json:"sender_number"`
	Recipient_number string          `json:"recipient_number"`
	Recipient_name   string          `json:"recipient_name"`
	New_balance      string          `json:"new_balance"`
	Transaction_type string          `json:"transaction_type"`
	Additionaldata   json.RawMessage `json:"additionaldata"`
	Transactionid    int             `json:"transactionid"`
	Userid           int             `json:"userid"`
}

func CreateTransaction(c *gin.Context) {
	body := Transaction{}
	data, err := c.GetRawData()
	if err != nil {
		c.AbortWithStatusJSON(400, "Transaction failed")
	}

	err = json.Unmarshal(data, &body)
	if err != nil {
		c.AbortWithStatusJSON(400, "Bad Input")
		return
	}
	_, err = database.DB.Exec("INSERT INTO  transactions (amount, currency, sender_number, recipient_number, recipient_name, new_balance, transaction_type, additionaldata, userid) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", body.Amount, body.Currency, body.Sender_number, body.Recipient_number, body.Recipient_name, body.New_balance, body.Transaction_type, body.Additionaldata, body.Userid)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(400, "Failed to create transaction")
	} else {
		c.JSON(http.StatusOK, "Transaction successful")
	}
	defer database.DB.Close()

}

func GetUser(c *gin.Context) {
	// Extract the userid parameter from the URL
	userid := c.Param("userid")

	// Query the database to get user info based on userid
	var userinfo User
	err := database.DB.QueryRow("SELECT * FROM users WHERE userid = $1", userid).
		Scan(&userinfo.Created, &userinfo.Name, &userinfo.Email, &userinfo.Phone_number, &userinfo.Additionaldata, &userinfo.Status, &userinfo.Userid)
	if err != nil {
		// If user not found, return 404 Not Found response
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Return the user info as JSON
	c.JSON(http.StatusOK, userinfo)
}

func GetTransaction(c *gin.Context) {
	transactionid := c.Param("transactionid")
	var trans Transaction
	err := database.DB.QueryRow("SELECT * FROM transactions WHERE transactionid = $1", transactionid).
		Scan(&trans.Amount, &trans.Currency, &trans.Sender_number, &trans.Recipient_number, &trans.Recipient_name, &trans.New_balance, &trans.Transaction_type, &trans.Additionaldata, &trans.Transactionid, &trans.Userid)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusNotFound, gin.H{"error": "Transaction not found"})
		return

	}
	c.JSON(http.StatusOK, trans)
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
