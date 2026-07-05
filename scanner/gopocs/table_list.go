package gopocs

import (
	"database/sql"
	"strings"
)

func dbTableListStr(db *sql.DB, driver string) string {
	var query string
	switch driver {
	case "postgres", "kingbase":
		query = "SELECT datname FROM pg_catalog.pg_database WHERE datistemplate = false LIMIT 5"
	case "mysql":
		query = "SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys') LIMIT 5"
	case "mssql":
		query = "SELECT TOP 15 name FROM sys.tables"
	case "oracle", "dm":
		query = "SELECT table_name FROM all_tables WHERE ROWNUM <= 15"
	default:
		return ""
	}
	rows, err := db.Query(query)
	if err != nil {
		return "<err>"
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ",")
}
