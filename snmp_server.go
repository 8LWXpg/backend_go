package main

import (
	"database/sql"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gosnmp/gosnmp"
)

func Listener() *gosnmp.TrapListener {
	listener := gosnmp.NewTrapListener()

	listener.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		fmt.Printf("got trap data from %s: %+v\n", addr.IP, packet)
		if packet.ErrorIndex != 0 {
			// TODO: handle error (email alert, frontend alert)
			fmt.Println(packet.Error.String())
			return
		}

		db, err := sql.Open("mysql", SQL_SOURCE)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer db.Close()

		stmt, err := db.Prepare("INSERT INTO " + DATA_TABLE + "(time, ip, event) VALUES(?, ?, ?)")
		if err != nil {
			fmt.Println(err)
			return
		}

		/* jsonBytes, err := json.Marshal(packet.Variables)
		if err != nil {
			fmt.Println("Error converting to JSON:", err)
			return
		}
		fmt.Println(string(jsonBytes)) */
		time := time.Now().Format("2006-01-02 15:04:05")
		var event strings.Builder
		for _, v := range packet.Variables {
			switch v.Type {
			case gosnmp.OctetString:
				message := fmt.Sprintf("string: %s", string(v.Value.([]byte)))
				fmt.Println(message)
				event.WriteString(message)
			default:
				message := fmt.Sprintf("type: %s, value: %v", v.Type, v.Value)
				fmt.Println(message)
				event.WriteString(message)
			}
		}

		_, err = stmt.Exec(time, addr.IP.String(), event.String())
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	return listener
}

func sendEmail(from string, to []string, subject string, body string) error {
	smtpHost := "localhost" // replace with your SMTP server if different
	smtpPort := "25"        // replace with your SMTP port if different
	auth := smtp.PlainAuth("", "your-username", "your-password", smtpHost)

	msg := "From: " + from + "\n" +
		"To: " + to[0] + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, []byte(msg))
}

func TestListener(t *testing.T) {
	Listener().Listen("localhost:162")
}
