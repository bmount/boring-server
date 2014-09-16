package auth

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	"log"
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

func dbput(bucket string, k []byte, v []byte) error {
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		err := b.Put(k, v)
		if err != nil {
			fmt.Println("dbput err:", err, k, v)
			return err
		}
		return nil
	})
	return err
}

func dbget(bucket string, k []byte) []byte {
	var rv []byte
	_ = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		rv = b.Get(k)
		return nil
	})
	return rv
}

func (u *User) Save() (err error) {
	bits := u.Serialize()
	if bits == nil {
		return errors.New("unlikely serialization error")
	}
	fmt.Println("uuid", u.Uuid, "bits", bits)
	err = dbput("users", []byte(u.Uuid), bits)
	if err != nil {
		fmt.Println("save user err, ", err)
		return err // tx.Rollback()
	}
	err = dbput("user-name", []byte(u.UniqueName), bits)
	if err != nil {
		log.Println("skipping invite-related name index err: ", err)
		return nil
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

func (u *User) Load() (*User, error) {
	fmt.Println("in load", *u, u.Uuid)
	if u.Uuid == "" && u.UniqueName == "" {
		return nil, errors.New("uninitialized")
	}
	var bits []byte
	var namebits []byte
	bits = dbget("users", []byte(u.Uuid))
	namebits = dbget("user-name", []byte(u.UniqueName))
	if bits == nil && namebits == nil {
		return nil, errors.New("no user")
	}
	if bits == nil {
		bits = namebits
	}
	fullUser := deserializeUser(bits)
	fmt.Println("fullUser", fullUser)
	return fullUser, nil
}
