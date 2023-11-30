package main

import (
	"database/sql"
	"fmt"
	"net"
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

		time := time.Now().Format("2006-01-02 15:04:05")
		var event strings.Builder
		for _, v := range packet.Variables {
			switch v.Type {
			case gosnmp.OctetString:
				b := v.Value.([]byte)
				fmt.Printf("OID: %s, string: %x\n", v.Name, b)
				event.WriteString(fmt.Sprintf("OID: %s, string: %x\n", v.Name, b))
			default:
				fmt.Printf("trap: %+v\n", v)
				event.WriteString(fmt.Sprintf("trap: %+v\n", v))
			}
		}
		// fmt.Printf("event:\n%s\n", event.String())
		_, err = stmt.Exec(time, addr.IP.String(), event.String())
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	return listener
}

func TestListener(t *testing.T) {
	Listener().Listen("localhost:162")
}
