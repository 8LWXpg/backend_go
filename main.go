package main

const (
	SQL_SOURCE = "root:root@tcp(localhost:3306)/network"
	DATA_TABLE = "trap_data"
	AUTH_TABLE = "auth"
)

func main() {
	// go func() {
	// Api_server().Run("localhost:8080")
	// }()
	Listener().Listen("0.0.0.0:162")
}
