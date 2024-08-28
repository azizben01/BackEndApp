package main

import (
	"ben/benaziz/BackEndApp/database"
	"context"

	// "crypto/rand"
	"database/sql"
	"encoding/base64"

	// "encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand" // for generating random 6 digits number
	"net/http"
	"os"
	"time"

	"strconv" // Import strconv for string to integer conversion

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
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
	router.POST("/RequestReset", RequestPasswordReset)
	router.POST("/ResetCode", VerifyResetCode)   // for verifying code
	router.POST("/ResetPassword", ResetPassword) // for updating new password in db
	router.DELETE("/deletetransactions/:transactionid", SoftDeleteTransaction)

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
	getTokenJSON()
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
	var req User

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad input"})
	}
	// body := User{}
	// data, err := ctx.GetRawData()
	// if err != nil {
	// 	ctx.AbortWithStatusJSON(400, "User is not defined")
	// 	return
	// }
	// err = json.Unmarshal(data, &body)
	// if err != nil {
	// 	ctx.AbortWithStatusJSON(400, "Bad Input")
	// 	return
	// }

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	req.Password = string(hashedPassword)

	_, err = database.DB.Exec("insert into users(username, email, phonenumber, password, additionaldata, status) values ($1,$2,$3,$4,$5,$6)", req.Username, req.Email, req.Phonenumber, req.Password, req.Additionaldata, req.Status)
	if err != nil {
		fmt.Println(err)
		// fmt.Println("HELLO HERE")
		ctx.AbortWithStatusJSON(400, "Could not create a new user")

	} else {
		ctx.JSON(http.StatusOK, "New user successfully created")
	}

	// send welcom email to user

	err = sendWelcomEmail(req.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send welcom email"})
		return
	}

	//defer database.DB.Close()
}

type Transaction struct {
	Username        string `json:"username"`
	Amount          int    `json:"amount"`
	Currency        string `json:"currency"`
	Senderphone     string `json:"senderphone"`
	Recipientphone  string `json:"recipientphone"`
	Recipientname   string `json:"recipientname"`
	Newbalance      string `json:"new_balance"`
	Transactiontype string `json:"transactiontype"`
	Additionaldata  string `json:"additionaldata"`
	Created         string `json:"created"`
	Transactionid   int    `json:"transactionid"`
	IsDeleted       bool   `json:"is_deleted"`
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

	_, err = database.DB.Exec("INSERT INTO transactions (username, amount, currency, senderphone, recipientphone, recipientname, newbalance, transactiontype, additionaldata, created) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", body.Username, body.Amount, body.Currency, body.Senderphone, body.Recipientphone, body.Recipientname, body.Newbalance, body.Transactiontype, body.Additionaldata, body.Created)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(400, "Failed to create transaction")
		return
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

// log in function
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

// transaction list function
func GetTransaction(ctx *gin.Context) {
	var transactions []Transaction
	rows, err := database.DB.Query("SELECT * FROM transactions WHERE is_deleted = FALSE")
	if err != nil {
		fmt.Println(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve transactions"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var trans Transaction
		err := rows.Scan(&trans.Transactionid, &trans.Username, &trans.Amount, &trans.Currency, &trans.Senderphone, &trans.Recipientphone, &trans.Recipientname, &trans.Newbalance, &trans.Transactiontype, &trans.Additionaldata, &trans.Created, &trans.IsDeleted)
		if err != nil {
			fmt.Println(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing transaction data"})
			return
		}
		transactions = append(transactions, trans)
	}

	ctx.JSON(http.StatusOK, transactions)
}
func SoftDeleteTransaction(ctx *gin.Context) {
	// Get the transaction ID as a string from the URL parameters
	transactionIDStr := ctx.Param("transactionid")

	// Convert the string transaction ID to an integer
	transactionID, err := strconv.Atoi(transactionIDStr)
	if err != nil {
		fmt.Println("Invalid transaction ID:", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid transaction ID"})
		return
	}
	// Prepare the SQL query
	query := "UPDATE transactions SET is_deleted = TRUE WHERE transactionid = $1"

	// Execute the query with the transaction ID
	_, err = database.DB.Exec(query, transactionID)
	if err != nil {
		fmt.Println("Error executing query:", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete transaction"})
		return
	}

	// respond with success
	ctx.JSON(http.StatusOK, gin.H{"message": "Transaction deleted successfully"})
}

// change mobile number function
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

// change password function
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

// delete account function
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

// from Maxence to generate token then send mail

func getTokenJSON() {
	ctx := context.Background()
	b, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)

	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}

	user := "me"
	r, err := srv.Users.Labels.List(user).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve labels: %v", err)
	}
	if len(r.Labels) == 0 {
		fmt.Println("No labels found.")
		return
	}
	fmt.Println("Labels:")
	for _, l := range r.Labels {
		fmt.Printf("- %s\n", l.Name)
	}
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code: %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

func sendResetEmail(userEmail string, code string) error {
	b, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	config, err := google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)
	ctx := context.Background()

	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}

	var message gmail.Message
	subject := "Password Reset Request"
	body := fmt.Sprintf("You requested a password reset. Use the code below to reset your password:\n\n%s", code) // Email body with the numeric code

	msg := []byte("From: 'me'\r\n" +
		"To: " + userEmail + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body)

	message.Raw = base64.URLEncoding.EncodeToString(msg)

	_, err = srv.Users.Messages.Send("me", &message).Do()
	if err != nil {
		return fmt.Errorf("Unable to send email: %v", err)
	}

	fmt.Println("Email sent successfully!")
	return nil
}

// generate random 6 digits code
func generateResetCode() (string, error) {
	// Generate a random 6-digit code
	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	return code, nil
}

// function for requesting the password reset code via email
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

	// Generate the reset code
	code, err := generateResetCode()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset code"})
		return
	}

	// Store the token in the database with an expiry time
	expiry := time.Now().Add(1 * time.Hour).UTC()

	_, err = database.DB.Exec("UPDATE users SET resettoken = $1, resettokenexpiry = $2 WHERE email = $3", code, expiry, req.Email)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store reset token"})
		return
	}
	// Send the password reset email
	err = sendResetEmail(user.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send password reset email"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
}

// function used to verify the reset code then allow the user to change their password
func VerifyResetCode(ctx *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	var storedCode string
	var expiry time.Time
	var email string

	// Find the user by the reset code

	err := database.DB.QueryRow("SELECT email, resettoken, resettokenexpiry FROM users WHERE resettoken = $1", req.Code).Scan(&email, &storedCode, &expiry)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired code"})
		return
	}

	expiry = expiry.UTC()
	if time.Now().UTC().After(expiry) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Code has expired"})
		return
	}

	if req.Code != storedCode {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}

	// If the code is valid, respond with success
	ctx.JSON(http.StatusOK, gin.H{"message": "Code verified", "email": email})
}

// function for updating the new password in the database
func ResetPassword(ctx *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Hash the new password before storing it in the database

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update the user's password and invalidate the reset token
	_, err = database.DB.Exec("UPDATE users SET password = $1, resettoken = NULL, resettokenexpiry = NULL WHERE email = $2", hashedPassword, req.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully"})
}

// function for updating your reset password in the database
// func NewPasswordReset(ctx *gin.Context) {
// 	var req struct {
// 		NewPassword     string `json:"newPassword"`
// 		ConfirmPassword string `json:"confirmPassword"`
// 		Token           string `json:"token"`
// 	}

// 	if err := ctx.ShouldBindJSON(&req); err != nil {
// 		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
// 		return
// 	}

// 	// Validate the passwords
// 	if req.NewPassword != req.ConfirmPassword {
// 		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
// 		return
// 	}

// 	// Verify the token and check expiration
// 	var username string
// 	var tokenExpiry time.Time
// 	err := database.DB.QueryRow("SELECT username, resettokenexpiry FROM users WHERE resettoken = $1", req.Token).Scan(&username, &tokenExpiry)
// 	if err == sql.ErrNoRows {
// 		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
// 		return
// 	} else if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate token"})
// 		return
// 	}

// 	// Check if the token has expired
// 	if time.Now().After(tokenExpiry) {
// 		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Token has expired"})
// 		return
// 	}

// 	// Hash the new password
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
// 		return
// 	}

// 	// Update the password in the database
// 	_, err = database.DB.Exec("UPDATE users SET password = $1, resettoken = NULL, resettokenexpiry = NULL WHERE username = $2", hashedPassword, username)
// 	if err != nil {
// 		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
// 		return
// 	}

// 	ctx.JSON(http.StatusOK, gin.H{"message": "Password successfully reset"})
// }

// send an email whenever you register
func sendWelcomEmail(userEmail string) error {
	b, err := os.ReadFile("credentials.json")
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	config, err := google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	client := getClient(config)
	ctx := context.Background()

	srv, err := gmail.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}

	var message gmail.Message
	subject := "New Use"
	body := fmt.Sprintf("Swiftpay team is welcoming you into SWIFTPAY. Enjoy your new transaction concept!! ")

	msg := []byte("From: 'me'\r\n" +
		"To: " + userEmail + "\r\n" +
		"Subject: " + subject + "\r\n\r\n" +
		body)

	message.Raw = base64.URLEncoding.EncodeToString(msg)

	_, err = srv.Users.Messages.Send("me", &message).Do()
	if err != nil {
		return fmt.Errorf("Unable to send email: %v", err)
	}

	fmt.Println("Email sent successfully!")
	return nil
}

// make so that when you want to reset your password you send a code via email and this same code is used to change the password.
// this is instead of sending a token
