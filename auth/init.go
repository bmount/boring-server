package auth

import (
	"errors"
	"os"
	"path"
	"time"
)

var (
	dataDir             string  = ""
	defaultDir          string  = "boring-server"
	configPrefix        string  = "BORING_SERVER_"
	keyRotationInterval float64 = 99.0
	numberOfKeys        int     = 3
	dbName              string  = "boring.db"
	cookieName          string  = "cookie"
)

type Opts struct {
	DataDir             string
	ConfigPrefix        string
	KeyRotationInterval float64
	NumberOfKeys        int
	DBName              string
	CookieName          string
}

var maxDuration time.Duration

func NewWithOpts(options Opts) error {
	if options.DataDir != "" {
		dataDir = options.DataDir
	}
	if options.ConfigPrefix != "" {
		configPrefix = options.ConfigPrefix
	}
	if options.DBName != "" {
		dbName = options.DBName
	}
	if options.CookieName != "" {
		cookieName = options.CookieName
	}
	if options.KeyRotationInterval != 0.0 {
		keyRotationInterval = options.KeyRotationInterval
	}
	if options.NumberOfKeys != 0 {
		numberOfKeys = options.NumberOfKeys
	}
	return New()
}

func New() error {
	maxDuration = time.Duration(int64(keyRotationInterval*3.6e12) * int64(numberOfKeys))
	dataDirFromEnv := os.Getenv(configPrefix + "DATA_DIR")
	if dataDirFromEnv != "" {
		dataDir = dataDirFromEnv
	}
	err := setPathDefaults()
	if err != nil {
		return err
	}
	if authKeyFile == "" {
		return errors.New("no keys available")
	}
	activeKeys, err = loadKeys()
	if err != nil {
		activeKeys, err = createKeys(numberOfKeys)
		if err != nil {
			return err
		} else {
			err = persistKeys(activeKeys)
			if err != nil {
				return err
			}
		}
	}
	err = initDb()
	return err
}

func setPathDefaults() error {
	home, err := homeDir()
	if err != nil {
		return err
	}
	if dataDir == "" {
		dataDir = path.Join(home, ".config", defaultDir)
		authKeyFile = path.Join(dataDir, "boring.keys")
		err = os.MkdirAll(dataDir, 0755)
		if err != nil {
			return err
		}
		return nil
	} else {
		err = os.MkdirAll(dataDir, 0755)
		if err != nil {
			return err
		}
		authKeyFile = path.Join(dataDir, "boring.keys")
		return nil
	}
	return nil
}
