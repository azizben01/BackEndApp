package main

import (
	"ben/benaziz/BackEndApp/database"
	"context"
	"strings"

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

	//"golang.org/x/text/number"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

func main() {
	router := gin.Default()
	database.ConnectDatabase()
	router.POST("/user", CreateUser)
	router.POST("/usertransaction", CreateUserTransaction)
	router.POST("/login", LoginUser)
	router.POST("/changeNumber", updatePhoneNumber)
	router.POST("/changePassword", updatePassword)
	router.GET("/transactions", GetUserTransaction)
	router.POST("/deleteAccount", deleteAccount)
	router.POST("/RequestReset", RequestPasswordReset)
	router.POST("/ResetCode", VerifyResetCode)   // for verifying code
	router.POST("/ResetPassword", ResetPassword) // for updating new password in db
	router.DELETE("/deletetransactions/:transactionid", SoftDeleteTransaction)
	// admnin routes
	router.POST("/createadmin", CreateAdmin)
	router.POST("/adminLogin", AdminLogin)
	router.POST("/admintransaction", CreateAdminTransaction)
	router.GET("/RetrieveEmployees", GetEmployees)
	router.GET("/Getadmintransaction", GetAdminTransaction)
	router.POST("/generateReport", generateReport)
	router.DELETE("/deleteAdmintransactions/:adminTransactionid", SoftDeleteAdminTransaction)
	router.DELETE("/deleteemployee/:username", deleteEmployee)
	router.POST("/requestCode", RequestAdminCode)
	router.POST("/VerifyAdminCode", VerifyAdminCode)

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

type Employees struct {
	Username            string    `json:"username"`
	Employeefullname    string    `json:"employeefullname"`
	Email               string    `json:"email"`
	Phonenumber         string    `json:"phonenumber"`
	Password            string    `json:"password"`
	Position            string    `json:"position"`
	Created				string    `json:"created"`
	Additionaldata      string    `json:"additionaldata"`
	Status              string    `json:"status"`
	ResetToken          *string    `json:"resetToken"`  // Pointer to string to handle NULL
	ResetTokenExpiry    *time.Time `json:"resetTokenExpiry"`
}

func CreateUser(ctx *gin.Context) {
	var req Employees

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad input"})
	}

	// Normalize the email to lowercase
	req.Email = strings.ToLower(req.Email)

	// Check if the email already exists
	var existingEmail string
	err := database.DB.QueryRow("SELECT email FROM employees WHERE email = $1", req.Email).Scan(&existingEmail)
	if err != nil && err != sql.ErrNoRows {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if existingEmail != "" {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Email is already in use"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	req.Password = string(hashedPassword)
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	req.Created = currentTime

	_, err = database.DB.Exec("insert into employees (employeefullname, username, email, phonenumber, password, position, created, additionaldata, status) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)", req.Employeefullname, req.Username, req.Email, req.Phonenumber, req.Password,req.Position, req.Created, req.Additionaldata, req.Status)
	if err != nil {
		fmt.Println(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create a new user"})
		return
	}

	// Send welcome email to user
	err = sendWelcomEmail(req.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send welcome email"})
		return
	}
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

func CreateUserTransaction(c *gin.Context) {
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

// log in function
func LoginUser(c *gin.Context) {
	var reqEmployee Employees
	if err := c.ShouldBindJSON(&reqEmployee); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Normalize the email to lowercase
	reqEmployee.Email = strings.ToLower(reqEmployee.Email)

	var storedEmployee Employees
	err := database.DB.QueryRow("SELECT username, employeefullname, email, phonenumber, password, position, additionaldata, status FROM employees WHERE email = $1", reqEmployee.Email).
		Scan(&storedEmployee.Username,&storedEmployee.Employeefullname, &storedEmployee.Email, &storedEmployee.Phonenumber, &storedEmployee.Password, &storedEmployee.Position, &storedEmployee.Additionaldata, &storedEmployee.Status)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			fmt.Println("databse error", err)
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedEmployee.Password), []byte(reqEmployee.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Login successful",
		"username":     storedEmployee.Username,
		"Fullname":     storedEmployee.Employeefullname,
		"email":        storedEmployee.Email,
		"phone_number": storedEmployee.Phonenumber,
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
func GetUserTransaction(ctx *gin.Context) {
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

	var storedUser Employees
	err := database.DB.QueryRow("SELECT phonenumber, username, email FROM employees WHERE phonenumber = $1", req.OldPhoneNumber).Scan(&storedUser.Phonenumber, &storedUser.Username, &storedUser.Email)
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

	var storedEmployee Employees
	err := database.DB.QueryRow("SELECT password, username, phonenumber, email FROM employees WHERE username = $1", req.Username).Scan(&storedEmployee.Password, &storedEmployee.Username, &storedEmployee.Phonenumber, &storedEmployee.Email)

	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect !!"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedEmployee.Password), []byte(req.OldPassword))
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

	_, err = database.DB.Exec("UPDATE employees SET password = $1 WHERE username = $2", string(hashedNewPassword), req.Username)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "Password updated successfully",
		"phone_number": storedEmployee.Phonenumber,
		"username":     storedEmployee.Username,
		"Phone_number": storedEmployee.Phonenumber,
		"email":        storedEmployee.Email,
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

	var storedEmployee Employees
	err := database.DB.QueryRow("SELECT password FROM employees WHERE username = $1", req.Username).Scan(&storedEmployee.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedEmployee.Password), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect password"})
		return
	}

	_, err = database.DB.Exec("DELETE FROM employees WHERE username = $1", req.Username)
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
	  // Normalize the email to lowercase
	  req.Email = strings.ToLower(req.Email)


	var employee Employees
	err := database.DB.QueryRow("SELECT username, email FROM employees WHERE email = $1", req.Email).Scan(&employee.Username, &employee.Email)
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

	_, err = database.DB.Exec("UPDATE employees SET resettoken = $1, resettokenexpiry = $2 WHERE email = $3", code, expiry, req.Email)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store reset token"})
		return
	}
	// Send the password reset email
	err = sendResetEmail(employee.Email, code)
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

	err := database.DB.QueryRow("SELECT email, resettoken, resettokenexpiry FROM employees WHERE resettoken = $1", req.Code).Scan(&email, &storedCode, &expiry)

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
	_, err = database.DB.Exec("UPDATE employees SET password = $1, resettoken = NULL, resettokenexpiry = NULL WHERE email = $2", hashedPassword, req.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully"})
}

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
	subject := "WELCOME TO YOU! "
	body := fmt.Sprintf("Swiftpay from Aziz is welcoming you into SWIFTPAY. Enjoy your new transaction concept and do not hesitate to contact us for any more information. ")

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

// Below are the functions related to admin
type Admin struct {
	AdminName        string    `json:"adminName"`
	Email            string    `json:"email"`
	Fullname	     string    `json:"fullname"`
	Phonenumber      string   `json:"phonenumber"`
	Password         string    `json:"password"`
	Status           string    `json:"status"`
	ResetToken          *string    `json:"resetToken"`  // Pointer to string to handle NULL
	ResetTokenExpiry    *time.Time `json:"resetTokenExpiry"`
	
}
// function for registering admin 
func CreateAdmin(ctx *gin.Context) {
	var req Admin

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "bad input"})
	}

	// Normalize the email to lowercase
	req.Email = strings.ToLower(req.Email)

	// Check if the email already exists
	var existingEmail string
	err := database.DB.QueryRow("SELECT email FROM admin WHERE email = $1", req.Email).Scan(&existingEmail)
	if err != nil && err != sql.ErrNoRows {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if existingEmail != "" {
		ctx.JSON(http.StatusConflict, gin.H{"error": "Email is already in use"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	req.Password = string(hashedPassword)

	_, err = database.DB.Exec("insert into admin (adminName, email, fullname, phonenumber, password, status) values ($1,$2,$3,$4,$5,$6)", req.AdminName, req.Email, req.Fullname, req.Phonenumber, req.Password, req.Status)
	if err != nil {
		fmt.Println(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create a new administrator"})
		return
	}

	// Send welcome email to user
	err = sendWelcomEmail(req.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send welcome email"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message":      "new administrator created successful",
		 })
}

	 // Function to log in as admin 
	 func AdminLogin(c *gin.Context) {
		var reqAdmin Admin
		if err := c.ShouldBindJSON(&reqAdmin); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Normalize the email to lowercase
	reqAdmin.Email = strings.ToLower(reqAdmin.Email)

		var storedAdmin Admin
		err := database.DB.QueryRow("SELECT adminname, email, password, fullname, phonenumber, status FROM admin WHERE email = $1", reqAdmin.Email).
			Scan(&storedAdmin.AdminName, &storedAdmin.Email, &storedAdmin.Password, &storedAdmin.Fullname,&storedAdmin.Phonenumber, &storedAdmin.Status)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			}
			return
		}
	
		err = bcrypt.CompareHashAndPassword([]byte(storedAdmin.Password), []byte(reqAdmin.Password))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		}
	
		c.JSON(http.StatusOK, gin.H{
			"message":      "Login successful",
			"adminname":    storedAdmin.AdminName,
			"email":        storedAdmin.Email,
			"phoneNumber":  storedAdmin.Phonenumber,
			"status":       storedAdmin.Status,
		})
	}

// function to display list of employees
func GetEmployees(ctx *gin.Context) {
    var employees []Employees

    rows, err := database.DB.Query("SELECT username, employeefullname, email, phonenumber, password, position, created, additionaldata, status, resettoken, resettokenexpiry FROM employees")
    if err != nil {
        fmt.Println(err)
        ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve employees"})
        return
    }
    defer rows.Close()

    for rows.Next() {
        var emp Employees
        // Scan nullable fields using pointers (e.g., *string for ResetToken)
        err := rows.Scan(&emp.Username, &emp.Employeefullname, &emp.Email, &emp.Phonenumber, &emp.Password, &emp.Position, &emp.Created, &emp.Additionaldata, &emp.Status, &emp.ResetToken, &emp.ResetTokenExpiry)
        if err != nil {
            fmt.Println(err)
            ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing employee data"})
            return
        }
        employees = append(employees, emp)
    }

    ctx.JSON(http.StatusOK, employees)
}

type adminTransaction struct {
	AdminTransactionid 	int `json:"adminTransactionid"`
	Adminname 			string`json:"adminname"`
	Amount 				int `json:"amount"`
	Currency			string`json:"currency"`
	Adminphone 			string`json:"adminphone"`
	Username 			string`json:"username"`
	Employeephone 		string`json:"employeephone"`
	Newbalance 			string`json:"newbalance"`
	Transactiontype 	string`json:"transactiontype"`
	Additionaldata 		string`json:"additionaldata"`
	Created 			string`json:"created"`
	Is_deleted 			bool `json:"is_deleted"`
}
// function to let admin make transactions 
func CreateAdminTransaction(c *gin.Context) {
	var reqtransaction adminTransaction
	if err := c.ShouldBindBodyWithJSON(&reqtransaction); err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "Bad admin Input"})

		return
	}
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	reqtransaction.Created = currentTime

	fmt.Println("adminname income:", reqtransaction.Adminname)
	fmt.Println("employeename income:", reqtransaction.Username)
	_, err := database.DB.Exec("INSERT INTO admintransactions (adminname, amount, currency, adminphone, username, employeephone, newbalance, transactiontype, additionaldata, created) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", reqtransaction.Adminname, reqtransaction.Amount, reqtransaction.Currency, reqtransaction.Adminphone, reqtransaction.Username, reqtransaction.Employeephone, reqtransaction.Newbalance, reqtransaction.Transactiontype, reqtransaction.Additionaldata, reqtransaction.Created)
	if err != nil {
		fmt.Println(err)
		c.AbortWithStatusJSON(400, "Failed to create admin transaction")
		return
	}
}

func GetAdminTransaction(ctx *gin.Context) {
	var transactions []adminTransaction
	rows, err := database.DB.Query("SELECT * FROM admintransactions WHERE is_deleted = FALSE")
	if err != nil {
		fmt.Println(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve admin transactions"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var trans adminTransaction
		err := rows.Scan(&trans.AdminTransactionid,&trans.Adminname, &trans.Amount, &trans.Currency, &trans.Adminphone,&trans.Username, &trans.Employeephone, &trans.Newbalance, &trans.Transactiontype, &trans.Additionaldata, &trans.Created, &trans.Is_deleted)
		if err != nil {
			fmt.Println(err)
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing admin transaction data"})
			return
		}
		transactions = append(transactions, trans)
	}

	ctx.JSON(http.StatusOK, transactions)
}


// type Report struct {
// 	Report_id  			 	 int    `json:"report_id"`
// 	Title    			 	 string  `json:"title"`
// 	Description 		 	 string    `json:"decription"`
// 	Createdby  			 	 string  `json:"createdby"`
// 	Period  			 	 string  `json:"period"`
// 	Numberofemployees 	 	 int    `json:"numberofemployees"`
// 	Numberoftransactions 	 int   `json:"numberoftransactions"`
// 	Highesttransaction   	 int   `json:"highesttransaction"`
// 	Lowesttransaction    	 int   `json:"lowesttransaction"`
// 	Averagetransactions  	 int    `json:"averagetransactions"`
// 	Totalamounttransferred   int    `json:"totalamounttransferred"`
// 	Created_at  		 	 string    `json:"created_at"`
// 	Additionaldata       	 string  `json:"additionaldata"`
// }


func SoftDeleteAdminTransaction(ctx *gin.Context) {
	// Get the transaction ID as a string from the URL parameters
	admintransactionIDStr := ctx.Param("adminTransactionid")

	// Convert the string transaction ID to an integer
	admintransactionID, err := strconv.Atoi(admintransactionIDStr)
	if err != nil {
		fmt.Println("Invalid transaction ID:", err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid admin transaction ID"})
		return
	}
	// Prepare the SQL query
	query := "UPDATE admintransactions SET is_deleted = TRUE WHERE admintransactionid = $1"

	// Execute the query with the transaction ID
	_, err = database.DB.Exec(query, admintransactionID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete admin transactions"})
		fmt.Println("failed to delete admin transaction:", err)
		return
	}

	// respond with success
	ctx.JSON(http.StatusOK, gin.H{"message": " admin Transaction deleted successfully"})
}





func deleteEmployee(c *gin.Context) {
	// Retrieve the username from the URL parameter or request body
	username := c.Param("username") // Assuming you're passing the username as a URL parameter

	// Check if the employee exists in the database
	var storedEmployee Employees
	err := database.DB.QueryRow("SELECT username FROM employees WHERE username = $1", username).Scan(&storedEmployee.Username)
	if err != nil {
		if err == sql.ErrNoRows {
			// If no employee is found, return an error
			c.JSON(http.StatusNotFound, gin.H{"error": "Employee not found"})
		} else {
			// Database error
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		}
		return
	}

	// Proceed to delete the employee from the database
	_, err = database.DB.Exec("DELETE FROM employees WHERE username = $1", username)
	if err != nil {
		// Handle any database-related error during deletion
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove employee"})
		fmt.Println(err)
		return
	}

	// Respond with a success message once the employee is deleted
	c.JSON(http.StatusOK, gin.H{"message": "Employee removed successfully"})
}

func RequestAdminCode(ctx *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
  fmt.Println("admin email requested:", req.Email)
  // Normalize the email to lowercase
	req.Email = strings.ToLower(req.Email)

	var admin Admin
	err := database.DB.QueryRow("SELECT adminname, email FROM admin WHERE email = $1", req.Email).Scan(&admin.AdminName, &admin.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "admin Email not found"})
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

	_, err = database.DB.Exec("UPDATE admin SET resettoken = $1, resettokenexpiry = $2 WHERE email = $3", code, expiry, req.Email)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store admin reset token"})
		return
	}
	// Send the password reset email
	err = sendResetEmail(admin.Email, code)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send admin password reset email"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "admin Password reset email sent"})
}

func VerifyAdminCode(ctx *gin.Context) {
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

	err := database.DB.QueryRow("SELECT email, resettoken, resettokenexpiry FROM admin WHERE resettoken = $1", req.Code).Scan(&email, &storedCode, &expiry)
      fmt.Println(&email)
      fmt.Println(&storedCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired admin code"})
		fmt.Println("invalid code:", err)
		return
	}

	expiry = expiry.UTC()
	if time.Now().UTC().After(expiry) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "admin Code has expired"})
		return
	}

	if req.Code != storedCode {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}

	// If the code is valid, respond with success
	ctx.JSON(http.StatusOK, gin.H{"message": "Code verified", "email": email})
}

type ReportRequest struct {
    Title         string `json:"title"`
    Description   string `json:"description"`
	Createdby	  string `json:"createdby"`
    Period        string `json:"period"`
	
}

type Report struct {
	Title              		  string `json:"title"`
	Description        		  string `json:"description"`
	Createdby		  		  string `json:"ceatedby"`
	Period             		  string `json:"period"`
	Numberofemployees  		  int `json:"numberofemployees"`
	TotalTransactions  		  int    `json:"total_transactions"`
	HighestTransaction 		  int    `json:"highest_transaction"`
	LowestTransaction  		  int    `json:"lowest_transaction"`
	Totalamounttransferred    int    `json:"totalamounttransferred"`
	CreatedAt          		  string `json:"created_at"`
}

// Determine the date range based on the period
	// var dateCondition string
	// switch req.Period {
	// case "monthly":
	// 	dateCondition = "NOW() - INTERVAL '30 days'"
	// case "trimonthly":
	// 	dateCondition = "NOW() - INTERVAL '90 days'"
	// case "yearly":
	// 	dateCondition = "NOW() - INTERVAL '365 days'"
	// default:
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid period"})
	// 	return
	// }

	// add average for the transactions
	

func generateReport(c *gin.Context) {
	var req ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	
fmt.Println(req.Createdby)
fmt.Println(req.Title)
	var report Report
	report.Title = req.Title
	report.Description = req.Description
	report.Period = req.Period
	report.Createdby = req.Createdby
	// Calculate report values
	err := database.DB.QueryRow("SELECT COUNT(*) FROM employees").Scan(&report.Numberofemployees)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate total employees"})
		
		return
	}
	err = database.DB.QueryRow("SELECT COUNT(*) FROM admintransactions ").Scan(&report.TotalTransactions) //WHERE created > NOW() - INTERVAL $1", dateCondition
	fmt.Println("Total transactions:", report.TotalTransactions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate total transactions"})
		return
	}
	

	err = database.DB.QueryRow("SELECT COALESCE(MAX(amount), 0) FROM admintransactions ").Scan(&report.HighestTransaction) // WHERE created > " + dateCondition
	fmt.Println("highest transaction:", report.HighestTransaction)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate highest transaction"})
		return
	}

	err = database.DB.QueryRow("SELECT COALESCE(MIN(amount), 0) FROM admintransactions").Scan(&report.LowestTransaction) // WHERE created > " + dateCondition
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate lowest transaction"})
		return
	}

	err = database.DB.QueryRow("SELECT COALESCE(SUM(amount), 0) FROM admintransactions ").Scan(&report.Totalamounttransferred) // WHERE created > " + dateCondition
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to calculate total outcome"})
		return
	}

	// Insert report into the database
	_, err = database.DB.Exec(`INSERT INTO reports (title, description, createdby, period, numberofemployees, numberoftransactions, highesttransaction, lowesttransaction, totalamounttransferred) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		req.Title, req.Description, req.Createdby, req.Period, report.Numberofemployees, report.TotalTransactions,
		report.HighestTransaction, report.LowestTransaction, report.Totalamounttransferred)
	if err != nil {
		fmt.Println("Report not saved:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save report"})
		return
	}

	// Set the created at field
	report.CreatedAt = time.Now().Format(time.RFC3339)

	// Return the generated report
	 c.JSON(http.StatusOK, report)

}