package sqlstore_test

import (
	"os"
	"testing"
)

var (
	databaseURL string
)

// Main test ...
func TestMain(m *testing.M) {
	databaseURL = os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "host=172.23.111.213 port=5433 dbname=restapi_test user=postgres sslmode=disable"
	}

	os.Exit(m.Run())
}
