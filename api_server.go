package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

type LoginField struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterField struct {
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type TrapData struct {
	Time  string
	IP    string
	Event string
}

func Api_server() *gin.Engine {
	r := gin.Default()
	store := cookie.NewStore([]byte("secret"))
	// 7 days
	store.Options(sessions.Options{MaxAge: 60 * 60 * 24 * 7})
	// TODO: set trusted proxies
	r.SetTrustedProxies([]string{"127.0.0.1"})
	r.Use(sessions.Sessions("login_session", store))

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
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
	// example: POST body: {"username":"admin","password":"admin"} http://localhost:8080/login
	r.POST("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("logged_in") == true {
			c.JSON(http.StatusOK, gin.H{"status": "you are already logged in"})
			return
		}

		var loginRequest LoginField

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
			session.Set("logged_in", true)
			session.Set("username", loginRequest.Username)
			session.Save()
			c.JSON(http.StatusOK, gin.H{"status": "you are logged in"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"status": "username or password mismatch"})
		}
	})

	// register
	// example: POST body: {"username":"admin","email":"email","password":"admin"} http://localhost:8080/register
	r.POST("/register", func(c *gin.Context) {
		var registerRequest RegisterField

		if err := c.ShouldBindJSON(&registerRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := register(registerRequest.Username, registerRequest.Email, registerRequest.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"status": "registration successful"})
	})

	return r
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

// authenticate validates whether the provided username and password are valid.
// It first opens a connection to the SQL data source, then hashes the provided password.
//
// Return values:
//
// (false, err) - Unexpected error (e.g. SQL connection error
//
// (false, nil) - Username or password does not match
//
// (true, nil) - Username and password match
func authenticate(username string, password string) (bool, error) {
	db, err := sql.Open("mysql", SQL_SOURCE)
	if err != nil {
		return false, err
	}
	defer db.Close()

	hashedPassword := hash(password)

	stmt, err := db.Prepare("SELECT username, password FROM " + AUTH_TABLE + " WHERE username=? AND password=?")
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

func register(username string, email string, password string) error {
	db, err := sql.Open("mysql", SQL_SOURCE)
	if err != nil {
		return err
	}
	defer db.Close()

	hashedPassword := hash(password)

	stmt, err := db.Prepare("INSERT INTO " + AUTH_TABLE + "(username, email, password) VALUES(?, ?, ?)")
	if err != nil {
		return err
	}

	_, err = stmt.Exec(username, email, hashedPassword)
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
