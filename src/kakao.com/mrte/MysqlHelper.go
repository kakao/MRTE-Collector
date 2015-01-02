package mrte


import (
	"fmt"
	"strings"
//	"container/list"
	"database/sql"
)

import _ "../../github.com/go-sql-driver/mysql"


var replThreadStates = [...]string{
	"Waiting for master", // Waiting for master to send event
	"Has read all relay log", // Has read all relay log; waiting for the slave I/O thread t
	"Waiting on empty queue",
	"Master has sent all binlog", // Master has sent all binlog to slave; waiting for binlog to be up
}

func GetSessionDefaultDatabase(host string, port int, user string, password string) []string{
	/* Current connect must be use lo device */
	connectionUrl := fmt.Sprintf("%s:%s@tcp(%s:%d)/", user, password, host, port)
    db, err := sql.Open("mysql", connectionUrl)
    if err != nil {
        panic(err.Error())  // Just for example purpose. You should use proper error handling instead of panic
    }
    defer db.Close()

	rows, err := db.Query("select host, db, state from information_schema.processlist where id<>connection_id()") /* Exception current connection */
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()
	
	sessions := make([]string, 0)
	// Prepare columns interface for fetching row
	cols, err := rows.Columns()
	if err != nil {
		fmt.Println("[ERROR] Failed to get columns", err)
		return sessions
	}

	// Result is your slice string.
	rawResult := make([][]byte, len(cols))
	result := make([]string, len(cols))

	dest := make([]interface{}, len(cols)) // A temporary interface{} slice
	for i, _ := range rawResult {
		dest[i] = &rawResult[i] // Put pointers to each string in the interface slice
	}
	
	// Fetch row data
	for rows.Next() {
		err = rows.Scan(dest...)
		if err !=nil {
			panic(err.Error())
		}
		
		for i, raw := range rawResult {
			if raw == nil {
				result[i] = ""
			} else {
				result[i] = string(raw)
			}
		}
		
		// Skip if this is replication thread
		if len(result[2])>0 {
			isReplThread := false
			for idx:=0; idx<len(replThreadStates); idx++ {
				if strings.HasPrefix(result[2], replThreadStates[idx]) {
					isReplThread = true
				}
			}
			
			if isReplThread {
				continue // Just skip it
			}
		}
		
		if len(result[0])>0 && len(result[1])>0 {
			sessions = append(sessions, result[0])
			sessions = append(sessions, result[1])
		}
	}
	
	return sessions
}