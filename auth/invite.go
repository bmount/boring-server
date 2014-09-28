package auth

import (
	"errors"
	"github.com/boltdb/bolt"
)

func NewUserInvitation(email string, admin bool, trust int) (*User, string, error) {
	// Email can be anything (handle, empty, etc.), it's here
	// as a way to keep track of outstanding invites without
	// setting names in advance
	u := &User{Email: email, Admin: admin, Trust: trust}
	uid, err := seqUid()
	if err != nil {
		return nil, "", err
	}
	u.Uuid = uid
	err = u.Save()
	if err != nil {
		return nil, "", err
	}
	inviteText, err := encode(u)
	if err != nil {
		return nil, "", err
	}
	return u, inviteText, nil
}

func FirstRunInvitation(rootUser string) (*User, string, error) {
	preexisting := true
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		c := b.Cursor()
		u0, _ := c.First()
		if u0 != nil {
			return errors.New("root account already set up")
		}
		preexisting = false
		return nil
	})
	if preexisting {
		return nil, "", errors.New("first run unavailable, users exist")
	}
	if rootUser == "" {
		return nil, "", errors.New("root username must not be empty string")
	}
	return NewUserInvitation("admin", true, 1e9)
}
