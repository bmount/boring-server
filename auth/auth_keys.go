package auth

import (
	"encoding/json"
	"errors"
	_ "fmt"
	"github.com/fernet/fernet-go"
	"io/ioutil"
	_ "net/http"
	"os"
	"os/user"
	"path"
)

var authKeyFile string
var activeKeys []*fernet.Key

func homeDir() (string, error) {
	var u *user.User
	u, err := user.Current()
	if u == nil {
		return "", errors.New("invalid user")
	}
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

func persistKeys(keys []*fernet.Key) error {
	dump := make([]string, len(keys))
	if len(keys) > *numberOfKeys {
		return errors.New("key count too big for setting")
	}
	for idx, key := range keys {
		dump[idx] = key.Encode()
	}
	bytes, err := json.Marshal(dump)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(authKeyFile, bytes, 0644)
	activeKeys = keys
	return err
}

func setPathDefaults() error {
	home, err := homeDir()
	if err != nil {
		return err
	}
	if *dataDir == "" {
		*dataDir = path.Join(home, ".config", defaultDir)
		authKeyFile = path.Join(*dataDir, "boring.keys")
		err = os.MkdirAll(*dataDir, 0755)
		if err != nil {
			return err
		}
		return nil
	} else {
		err = os.MkdirAll(*dataDir, 0755)
		if err != nil {
			return err
		}
		authKeyFile = path.Join(*dataDir, "boring.keys")
		return nil
	}
	return nil
}

func RotateActiveKeys() error {
	newKey := &fernet.Key{}
	err := newKey.Generate()
	if err != nil {
		return err
	}
	numKeys := *numberOfKeys
	newKeys := make([]*fernet.Key, numKeys)
	newKeys[0] = newKey
	if numKeys == len(activeKeys) {
		for i, k := range activeKeys {
			if i == numKeys-1 {
				continue
			} else {
				newKeys[i+1] = k
			}
		}
		err = persistKeys(newKeys)
		if err != nil {
			return err
		}
	} else {
		// Rotating keys, when the new length is different from previous,
		// will be in effect a reset
		k, err := createKeys(*numberOfKeys)
		if err != nil {
			return err
		}
		err = persistKeys(k)
		return err
	}
	return nil
}

func ResetKeys() error {
	keys, err := createKeys(*numberOfKeys)
	if err != nil {
		return err
	}
	err = persistKeys(keys)
	if err != nil {
		return err
	}
	return nil
}

func createKeys(n int) ([]*fernet.Key, error) {
	keys := make([]*fernet.Key, n)
	for idx := 0; idx < n; idx++ {
		k := &fernet.Key{}
		err := k.Generate()
		if err != nil {
			return nil, err
		}
		keys[idx] = k
	}
	return keys, nil
}

func loadKeys() ([]*fernet.Key, error) {
	var encodedKeys []string
	prevKeys, err := ioutil.ReadFile(authKeyFile)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(prevKeys, &encodedKeys)
	if err != nil {
		return nil, err
	}
	if len(encodedKeys) != *numberOfKeys {
		return nil, errors.New("cannot load sufficient")
	}
	decodedKeys := make([]*fernet.Key, *numberOfKeys)
	for idx, val := range encodedKeys {
		decodedKey, err := fernet.DecodeKey(val)
		if err != nil {
			return nil, err
		}
		decodedKeys[idx] = decodedKey
	}
	return decodedKeys, nil
}

func decode(msg string) []byte {
	return fernet.VerifyAndDecrypt([]byte(msg), maxDuration, activeKeys)
}

func encode(msg interface{}) (string, error) {
	pre, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	post, err := fernet.EncryptAndSign(pre, activeKeys[0])
	return string(post), err
}
