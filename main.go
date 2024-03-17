package main

import (
	"ben/benaziz/BackEndApp/Database"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize the database
	db := Database.GetDatabase()
	defer db.db.Close() // Close the database connection when main function exits

	// Initialize the database tables
	db.InitDatabase()

	// Create a new Gin router
	r := gin.Default()

	// Define a route
	r.GET("/", func(c *gin.Context) {
		// Start a database transaction
		tx := db.StartTransaction()
		defer db.Rollback(tx) // Rollback the transaction if an error occurs
		// Perform a database query
		result, err := db.Read(tx, "SELECT current_date")
		if err != nil {
			c.JSON(500, gin.H{"error": "Internal Server Error"})
			return
		}
		defer result.Close() // Close the result set when done with it

		// Iterate over the query results
		var users []string
		for i := 0; i < result.Size(); i++ {
			user := result.Get(i)
			users = append(users, user.GetString(i, "current_date")) // Assuming current_date is the column name
		}

		// Commit the transaction
		if err := db.Commit(tx); err != nil {
			c.JSON(500, gin.H{"error": "Internal Server Error"})
			return
		}

		// Return the query results as JSON
		c.JSON(200, gin.H{"users": users})
	})

	// Run the server on port 1010
	r.Run(":1010")
}
