package auth

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	"path"
)

var db *bolt.DB

func initDb() error {
	var err error
	db, err = bolt.Open(path.Join(dataDir, dbName), 0644, nil)
	if err != nil {
		return errors.New("unable to access user db")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		var err error
		_, err = tx.CreateBucketIfNotExists([]byte("users"))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte("user-name"))
		if err != nil {
			return err
		}
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

func (u *User) Serialize() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(u)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}

func deserializeUser(bits []byte) *User {
	var u *User
	buf := bytes.NewBuffer(bits)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&u)
	if err != nil {
		fmt.Println("deserialize error", err)
		return nil
	}
	return u
}

func dbput(bucket, k string, v []byte) error {
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		err := b.Put([]byte(k), []byte(v))
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func dbget(bucket, k string) []byte {
	var rv []byte
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		rv = b.Get([]byte(k))
		return nil
	})
	return rv
}

func (u *User) Save() (err error) {
	bits := u.Serialize()
	if bits == nil {
		return errors.New("unlikely serialization error")
	}
	err = dbput("users", u.Uuid, bits)
	if err != nil {
		return err
	}
	if u.UniqueName != "" {
		err = dbput("user-name", u.UniqueName, bits)
		if err != nil {
			return err
		}
	}
	return nil
}

func (u *User) ChangeName(newName string) error {
	if u.UniqueName == "" {
		return errors.New("nothing to change")
	}
	err := db.Update(func(tx *bolt.Tx) error {
		userNameIdx := tx.Bucket([]byte("user-name"))
		userStore := tx.Bucket([]byte("user-name"))
		taken := userNameIdx.Get([]byte(newName))
		oldName := u.UniqueName
		if taken != nil {
			return errors.New("name unavailable")
		}
		u.UniqueName = newName
		val := u.Serialize()
		err := userStore.Put([]byte(u.Uuid), val)
		if err != nil {
			return err
		}
		err = userNameIdx.Put([]byte(newName), val)
		if err != nil {
			return err
		}
		err = userNameIdx.Delete([]byte(oldName))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (u *User) Load() (*User, error) {
	if u.Uuid == "" && u.UniqueName == "" {
		return nil, errors.New("uninitialized")
	}
	var bits []byte
	var namebits []byte
	bits = dbget("users", u.Uuid)
	namebits = dbget("user-name", u.UniqueName)
	if bits == nil && namebits == nil {
		return nil, errors.New("no user")
	}
	if bits == nil {
		bits = namebits
	}
	fullUser := deserializeUser(bits)
	return fullUser, nil
}
