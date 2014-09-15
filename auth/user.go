package auth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/json"
	"net/http"
	"time"
)

type User struct {
	EncryptedPassword string                 `json:-`
	Uuid              string                 `json:uuid`
	UniqueName        string                 `json:name`
	Email             string                 `json:-`
	Admin             bool                   `json:adm`
	Trust             int                    `json:trust`
	Active            bool                   `json:-`
	LastSeen          time.Time              `json:-`
	Meta              map[string]interface{} `json:-`
}

func (u *User) Cookie() (*http.Cookie, error) {
	encoded, err := encode(u)
	if err != nil {
		return nil, err
	}
	cookie := &http.Cookie{
		Name:  *cookieName,
		Value: encoded,
		Path:  "/",
	}
	return cookie, nil
}

func getSession(r *http.Request) (u User) {
	cookie, err := r.Cookie(*cookieName)
	if err != nil {
		return u
	}
	msg := decode(cookie.Value)
	if msg == nil {
		return u
	}
	err = json.Unmarshal(msg, &u)
	if err != nil {
		return u
	}
	return u
}

func (u *User) setSession(w http.ResponseWriter) (err error) {
	cookie, err := u.Cookie()
	if err != nil {
		return
	}
	http.SetCookie(w, cookie)
	return
}

func (u *User) overwriteSession(w http.ResponseWriter) error {
	/* err := http.SetCookie(w, &http.Cookie{
		Name:  *cookieName,
		Value: "thanks_for_visiting",
		Path:  "/",
	}) */
	return nil
}

func NewUser(email, password string, admin bool, trust int) (u *User, err error) {
	u = &User{Admin: admin, Trust: trust, Email: email}
	err = u.CreatePasswordHash(password)
	return
}

func (u *User) CreatePasswordHash(pw string) (err error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
	if err != nil {
		return
	}
	u.EncryptedPassword = string(hash)
	err = nil
	return
}

func BaseQuery() (bq string) {
	bq = `select ... `
	return
}
