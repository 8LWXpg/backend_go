package main

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gosnmp/gosnmp"
)

const (
	SQL_SOURCE = "root:root@tcp(localhost:3306)/network"
	DATA_TABLE = "trap_data"
	AUTH_TABLE = "auth"
)

func listener() *gosnmp.TrapListener {
	listener := gosnmp.NewTrapListener()

	listener.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		fmt.Printf("got trap data from %s: %+v", addr.IP, packet)
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

		time := time.Now().Format("2006-01-02 15:04:05")
		_, err = stmt.Exec(addr.IP.String(), packet.MsgFlags.String(), time)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	return listener
}

func main() {
	// go func() {
	Api_server().Run(":8080")
	// }()
	// listener().Listen("")
}
