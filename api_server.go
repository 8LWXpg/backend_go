package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type InputField struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type TrapData struct {
	Time  string
	IP    string
	Event string
}

func Api_server() {
	r := gin.Default()
	// TODO: set trusted proxies
	r.SetTrustedProxies([]string{"127.0.0.1"})

	// hello world
	// example: http://localhost:8080/hello
	r.GET("/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "hello world"})
	})

	// post test
	// example: POST '{"message":"hello"}' http://localhost:8080/test
	r.POST("/test", func(c *gin.Context) {
		msg := c.PostForm("message")

		c.JSON(http.StatusOK, gin.H{"message": msg})
	})

	// query data between start and end time
	// example: http://localhost:8080/data?start=2020-01-01&end=2020-01-02
	r.GET("/data", func(c *gin.Context) {
		start := c.Query("start")
		end := c.Query("end")

		data, err := queryData(start, end)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, data)
	})

	// login
	// example: POST '{"username":"admin","password":"admin"}' http://localhost:8080/login
	r.POST("/login", func(c *gin.Context) {
		var loginRequest InputField

		if err := c.ShouldBindJSON(&loginRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Authenticate the user
		status, err := authenticate(loginRequest.Username, loginRequest.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if status {
			c.JSON(http.StatusOK, gin.H{"status": "you are logged in"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "unauthorized"})
		}
	})

	// register
	// example: POST '{"username":"admin","password":"admin"}' http://localhost:8080/register
	r.POST("/register", func(c *gin.Context) {
		var registerRequest InputField

		if err := c.ShouldBindJSON(&registerRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := register(registerRequest.Username, registerRequest.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"status": "registration successful"})
	})

	if err := r.Run(); err != nil {
		fmt.Printf("Server failed to start: %v\n", err)
	}
}

func queryData(start string, end string) ([]TrapData, error) {
	db, err := sql.Open("mysql", SQL_SOURCE)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT * FROM "+DATA_TABLE+" WHERE time BETWEEN ? AND ?", start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []TrapData
	for rows.Next() {
		var r TrapData
		err := rows.Scan(&r.Time, &r.IP, &r.Event)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return results, nil
}

func authenticate(username string, password string) (bool, error) {
	db, err := sql.Open("mysql", SQL_SOURCE)
	if err != nil {
		return false, err
	}
	defer db.Close()

	hashedPassword := hash(password)

	stmt, err := db.Prepare("SELECT * FROM " + AUTH_TABLE + " WHERE username=? AND password=?")
	if err != nil {
		return false, err
	}

	row := stmt.QueryRow(username, hashedPassword)

	var retrievedUsername, retrievedPassword string
	err = row.Scan(&retrievedUsername, &retrievedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			// Username and password do not match
			return false, nil
		}
		// Unexpected error
		return false, err
	}

	// Username and password match
	return true, nil
}

func register(username string, password string) error {
	db, err := sql.Open("mysql", SQL_SOURCE)
	if err != nil {
		return err
	}
	defer db.Close()

	hashedPassword := hash(password)

	stmt, err := db.Prepare("INSERT INTO " + AUTH_TABLE + "(username, password) VALUES(?, ?)")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(username, hashedPassword)
	if err != nil {
		return err
	}

	return nil
}

// incase you want to change the hashing algorithm
func hash(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}
