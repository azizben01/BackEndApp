package main

import (
	"ben/benaziz/BackEndApp/database"
	"crypto/rand" // import for generating unique token
	"database/sql"
	"encoding/hex" // import for generating unique token
	"encoding/json"
	"fmt"
	"net/http"

	"net/smtp"
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
	router.POST("/changeNumber", updatePhoneNumber)
	router.POST("/changePassword", updatePassword)
	router.GET("/transactions", GetTransaction)
	router.POST("/deleteAccount", deleteAccount)
	router.POST("/requestsEmail", RequestPasswordReset)

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
	Username         string    `json:"username"`
	Email            string    `json:"email"`
	Phonenumber      string    `json:"phonenumber"`
	Password         string    `json:"password"`
	Additionaldata   string    `json:"additionaldata"`
	Status           string    `json:"status"`
	ResetToken       string    `json:"resetToken"`
	ResetTokenExpiry time.Time `json:"resetTokenExpiry"`
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

	_, err = database.DB.Exec("insert into users(username, email, phonenumber, password, additionaldata, status) values ($1,$2,$3,$4,$5,$6)", body.Username, body.Email, body.Phonenumber, body.Password, body.Additionaldata, body.Status)
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
	Username        string `json:"username"`
	Amount          int    `json:"amount"`
	Currency        string `json:"currency"`
	Senderphone     string `json:"sender_phone"`
	Recipientphone  string `json:"recipient_phone"`
	Recipientname   string `json:"recipient_name"`
	Newbalance      string `json:"new_balance"`
	Transactiontype string `json:"transaction_type"`
	Additionaldata  string `json:"additionaldata"`
	Created         string `json:"created"`
	Transactionid   int    `json:"transactionid"`
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

	fmt.Println("Username:", body.Username)
	fmt.Println("amount:", body.Amount)

	_, err = database.DB.Exec("INSERT INTO transactions (username, amount, currency, senderphone, recipientphone, recipientname, newbalance, transactiontype, additionaldata, created) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", body.Username, body.Amount, body.Currency, body.Senderphone, body.Recipientphone, body.Recipientname, body.Newbalance, body.Transactiontype, body.Additionaldata, body.Created)
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
		Scan(&userinfo.Username, &userinfo.Email, &userinfo.Phonenumber, &userinfo.Password, &userinfo.Additionaldata, &userinfo.Status)
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
	err := database.DB.QueryRow("SELECT username, email, phonenumber, password, additionaldata, status FROM users WHERE email = $1", reqUser.Email).
		Scan(&storedUser.Username, &storedUser.Email, &storedUser.Phonenumber, &storedUser.Password, &storedUser.Additionaldata, &storedUser.Status)
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

	c.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"username":     storedUser.Username,
		"email":        storedUser.Email,
		"phone_number": storedUser.Phonenumber,
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
		var trans Transaction
		err := rows.Scan(&trans.Transactionid, &trans.Username, &trans.Amount, &trans.Currency, &trans.Senderphone, &trans.Recipientphone, &trans.Recipientname, &trans.Newbalance, &trans.Transactiontype, &trans.Additionaldata, &trans.Created)
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

func updatePhoneNumber(c *gin.Context) {
	var req struct {
		OldPhoneNumber string `json:"oldPhoneNumber"`
		NewPhoneNumber string `json:"newPhoneNumber"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedUser User
	err := database.DB.QueryRow("SELECT phonenumber, username, email FROM users WHERE phonenumber = $1", req.OldPhoneNumber).Scan(&storedUser.Phonenumber, &storedUser.Username, &storedUser.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Old phone number does not match our records"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	_, err = database.DB.Exec("UPDATE users SET phonenumber = $1 WHERE phonenumber = $2", req.NewPhoneNumber, req.OldPhoneNumber)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update phone number"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Phone number updated successfully",
		"phone_number": req.NewPhoneNumber,
		"username":     storedUser.Username,
		"email":        storedUser.Email,
	})
}

func updatePassword(c *gin.Context) {
	var req struct {
		Username     string `json:"username"`
		Email        string `json:"email"`
		Phone_number string `json:"phonenumber"`
		OldPassword  string `json:"oldPassword"`
		NewPassword  string `json:"newPassword"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedUser User
	err := database.DB.QueryRow("SELECT password, username, phonenumber, email FROM users WHERE username = $1", req.Username).Scan(&storedUser.Password, &storedUser.Username, &storedUser.Phonenumber, &storedUser.Email)

	fmt.Println("current password is 1: ", req.OldPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect !!"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	fmt.Println("Provided old password:", req.OldPassword)
	fmt.Println("Stored hashed password:", storedUser.Password)

	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(req.OldPassword))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect."})
		return
	}

	// Hash the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	_, err = database.DB.Exec("UPDATE users SET password = $1 WHERE username = $2", string(hashedNewPassword), req.Username)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Password updated successfully",
		"phone_number": storedUser.Phonenumber,
		"username":     storedUser.Username,
		"Phone_number": storedUser.Phonenumber,
		"email":        storedUser.Email,
	})
}

func deleteAccount(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedUser User
	err := database.DB.QueryRow("SELECT password FROM users WHERE username = $1", req.Username).Scan(&storedUser.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect password"})
		return
	}

	_, err = database.DB.Exec("DELETE FROM users WHERE username = $1", req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete account"})
		fmt.Println(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account deleted successfully"})
}

// below is the trials for resetting the password

func generateResetToken() (string, error) { // generates the unique token allowing to reset the password
	tokenBytes := make([]byte, 32)

	_, err := rand.Read(tokenBytes)
	fmt.Println("token has been generated:", tokenBytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(tokenBytes), nil
}

// func sendResetEmail(toEmail, resetURL string) error { // sends the reset email to the user
// 	from := "Benazizsang1@gmail.com"
// 	password := "BAsuccess2001"

// 	subject := "Password Reset Request"
// 	message := fmt.Sprintf("To reset your password, click the following link: %s", resetURL)

// 	auth := smtp.PlainAuth("", from, password, "smtp.gmail.com") // Configures the authentication details for sending the email.
// 	msg := []byte("To: " + toEmail + "\r\n" +
// 		"Subject: " + subject + "\r\n" +
// 		"\r\n" + // this just adds a new line to separate
// 		message + "\r\n")

// 	err := smtp.SendMail("smtp.gmail.com:587", auth, from, []string{toEmail}, msg) // this line is the one sending the email using smtp server.
// 	if err != nil {
// 		return err
// 	}
// 	// smtp.gmail.com:587 is The SMTP server address and port for Gmail.
// 	// []string{toEmail} is the recipient's email address.

// 	return nil
// }

func sendResetEmail(from string, to []string, subject string, body string) error {
	// Setup email authentication (change this to your credentials)
	auth := smtp.PlainAuth("", from, "BAsuccess2001", "smtp.gmail.com")

	// Create the email message
	msg := []byte("To: " + to[0] + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	// Send the email
	err := smtp.SendMail("smtp.gmail.com:587", auth, from, to, msg)
	return err
}

func RequestPasswordReset(ctx *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var user User
	err := database.DB.QueryRow("SELECT username, email FROM users WHERE email = $1", req.Email).Scan(&user.Username, &user.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Email not found"})
		return
	}

	token, err := generateResetToken()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset token"})
		return
	}
	expiry := time.Now().Add(1 * time.Hour)

	_, err = database.DB.Exec("UPDATE users SET resettoken = $1, resettokenexpiry = $2 WHERE email = $3", token, expiry, req.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store reset token"})
		fmt.Println("no store token", err)
		return
	} else {
		fmt.Println("reset token successfully stored")
	}

	resetURL := fmt.Sprintf("https://mywebsite.com/reset-passwordTEST?token=%s", token)
	from := "Benazizsang1@gmail.com"
	to := []string{user.Email}
	subject := "Password Reset Request"
	body := fmt.Sprintf("Hello %s,\n\nPlease use the following link to reset your password:\n%s\n\nIf you did not request a password reset, please ignore this email.", user.Username, resetURL)

	err = sendResetEmail(from, to, subject, body)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send reset email"})
		fmt.Println("email not sent:", err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset link has been sent to your email"})
}

// 	resetURL := fmt.Sprintf("https://mywebsite.com/thisisthetest?token=%s", token)
// 	err = sendResetEmail(user.Email, resetURL)
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send reset email"})
// 		fmt.Println("email with token not sent", err)
// 		return
// 	} else {
// 		fmt.Println("email with token successfully sent to", "reseturl", resetURL, "or useremail", user.Email)
// 	}

// 	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset link has been sent to your email"})
// }
