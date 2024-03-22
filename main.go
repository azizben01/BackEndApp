package main

import (
	"ben/benaziz/BackEndApp/database"
	"encoding/json"
	"fmt"

	//"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	router.POST("/", addUser)
	database.ConnectDatabase()

	router.GET("/", func(context *gin.Context) {
		context.JSON(http.StatusOK, gin.H{
			"message": "Welcome",
		})
	})
	err := router.Run(":1010")
	if err != nil {
		panic(err)
	}

}

type User struct {
	Name     string
	Password string
}

func addUser(ctx *gin.Context) {
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
	//log.Println("Reach here")
	_, err = database.DB.Exec("insert into newUser(name,password) values ($1,$2)", body.Name, body.Password)
	if err != nil {
		fmt.Println(err)
		ctx.AbortWithStatusJSON(400, "Could not create a new user")

	} else {
		ctx.JSON(http.StatusOK, "New user successfully created")
	}
	defer database.DB.Close()

}
