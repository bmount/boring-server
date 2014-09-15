package auth

import (
	"flag"
	"os"
	"time"
)

var (
	dataDir             = flag.String("data_dir", "", "specify location of session keys (default: ~/.config/boring-server/)")
	defaultDir   string = "boring-server"
	configPrefix        = flag.String("config_prefix", "BORING_SERVER_",
		"prefix for config from environment variable, default BORING_SERVER_ (ie BORING_SERVER_DATA_DIR")
	keyRotationInterval = flag.Float64("key_rotation_interval", 99.0, "hours per key rotation (session lifespan = number of keys * rotation interval)")
	numberOfKeys        = flag.Int("number_of_keys", 3, "number of keys, defaults to 3")
	dbName              = flag.String("database_name", "boring.db", "name of user db (defaults to 'boring.db)'")
	cookieName          = flag.String("cookie_name", "cookie", "cookie name")
)

var maxDuration time.Duration

func init() {
	flag.Parse()
	maxDuration = time.Duration(int64(*keyRotationInterval*3.6e12) * int64(*numberOfKeys))
	dataDirFromEnv := os.Getenv(*configPrefix + "DATA_DIR")
	if dataDirFromEnv != "" {
		*dataDir = dataDirFromEnv
	}
	err := setPathDefaults()
	if err != nil {
		panic(err)
	}
	if authKeyFile == "" {
		panic("no keys available")
	}
	activeKeys, err = loadKeys()
	if err != nil {
		activeKeys, err = createKeys(*numberOfKeys)
		if err != nil {
			panic(err)
		} else {
			err = persistKeys(activeKeys)
			if err != nil {
				panic(err)
			}
		}
	}
	initDb()
}
