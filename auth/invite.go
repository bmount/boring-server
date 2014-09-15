package auth

import (
	"fmt"
	seq "github.com/streadway/simpleuuid"
	"time"
)

func NewUserInvitation(email string, admin bool, trust int) (*User, string, error) {
	u := &User{Email: email, Admin: admin, Trust: trust}
	uid, err := seq.NewTime(time.Now())
	if err != nil {
		return u, "", err
	}
	u.Uuid = uid.String()
	fmt.Println("generating user in NewUserInvitation", u, "new invite uid", string(u.Uuid), "with fn call", uid.String())
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
