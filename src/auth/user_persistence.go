package auth

import (
	"bytes"
	"encoding/gob"
	"errors"
	"github.com/boltdb/bolt"
	"log"
	"path"
)

var db *bolt.DB
var userStore *bolt.Bucket
var userNameIdx *bolt.Bucket

func initDb() {
	var err error
	db, err = bolt.Open(path.Join(*dataDir, *dbName), 0644, nil)
	if err != nil {
		panic("unable to access user db")
	}
	err = db.Update(func(tx *bolt.Tx) error {
		var err error
		userStore, err = tx.CreateBucketIfNotExists([]byte("users"))
		if err != nil {
			return err
		}
		userNameIdx, err = tx.CreateBucketIfNotExists([]byte("user-name"))
		if err != nil {
			return err
		}
		return err
	})
	if err != nil {
		panic(err)
	}
}

func (u *User) Retrieve() error {
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
	err := dec.Decode(u)
	if err != nil {
		return nil
	}
	return u
}

func (u *User) Save() (err error) {
	err = db.Update(func(tx *bolt.Tx) error {
		bits := u.Serialize()
		if bits == nil {
			log.Println("unlikely serialization error")
			return tx.Rollback()
		}
		err = userStore.Put(u.Uuid, bits)
		if err != nil {
			log.Println(err)
			return tx.Rollback()
		}
		err = userNameIdx.Put([]byte(u.UniqueName), bits)
		if err != nil {
			log.Println(err)
			return tx.Rollback()
		}
		return tx.Commit()
	})
	return
}

func (u *User) ChangeName(newName string) error {
	if u.UniqueName == "" {
		return errors.New("nothing to change")
	}
	err := db.Update(func(tx *bolt.Tx) error {
		taken := userNameIdx.Get([]byte(newName))
		oldName := u.UniqueName
		if taken != nil {
			return errors.New("name unavailable")
		}
		u.UniqueName = newName
		val := u.Serialize()
		err := userStore.Put(u.Uuid, val)
		if err != nil {
			log.Println(err)
			return tx.Rollback()
		}
		err = userNameIdx.Put([]byte(newName), val)
		if err != nil {
			log.Println(err)
			return tx.Rollback()
		}
		err = userNameIdx.Delete([]byte(oldName))
		if err != nil {
			log.Println(err)
			return tx.Rollback()
		}
		return tx.Commit()
	})
	if err != nil {
		return err
	}
	return nil
}

func (u *User) Load() error {
	bits := userStore.Get(u.Uuid)
	if bits == nil {
		return errors.New("no user")
	}
	fullUser := deserializeUser(bits)
	u = fullUser
	return nil
}
