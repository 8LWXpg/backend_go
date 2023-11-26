package main

import (
	"database/sql"
	"fmt"
	"log"
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
		time := time.Now().Format("2006-01-02 15:04:05")
		fmt.Printf("got trap data from %s: %+v", addr.IP, packet)

		db, err := sql.Open("mysql", SQL_SOURCE)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		stmt, err := db.Prepare("INSERT INTO " + DATA_TABLE + "(time, ip, event) VALUES(?, ?, ?)")
		if err != nil {
			log.Fatal(err)
		}

		_, err = stmt.Exec(addr.IP.String(), packet.MsgFlags.String(), time)
		if err != nil {
			log.Fatal(err)
		}
	}

	return listener
}

func main() {
	// go func() {
	Api_server()
	// }()
	// listener().Listen("")
}
