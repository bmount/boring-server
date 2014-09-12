package auth

import (
	"github.com/boltdb/bolt"
	"path"
)

var db *bolt.DB

func initDb() {
	var err error
	db, err = bolt.Open(path.Join(*dataDir, *dbName))
	if err != nil {
		panic("unable to access user db")
	}
}
