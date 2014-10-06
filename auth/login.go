package auth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

func LoginByName(name, givenPw string) (error, *User) {
	u := &User{UniqueName: name}
	u, err := (&u).Load()
	if err != nil || u == nil {
		return errors.New("unauthorized"), nil
	}
	authed := bcrypt.CompareHashAndPassword([]byte(u.EncryptedPassword), []byte(givenPw))
	if authed == nil {
		return authed, u
	}
	return authed, nil
}

func acceptInvite(userName, pw, invitation string) (*User, error) {
	var u *User
	takenName := dbget("user-name", userName)
	if takenName != nil {
		return nil, errors.New("name taken")
	}
	userBits := decode(invitation)
	if userBits != nil && pw != "" {
		err := json.Unmarshal(userBits, &u)
		if err != nil {
			return nil, err
		}
		u, err = u.Load()
		if err != nil {
			return nil, err
		}
		if u.EncryptedPassword != "" {
			return nil, errors.New("previously accepted invitation")
		}
		pwHash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		u.UniqueName = userName
		u.EncryptedPassword = string(pwHash)
		err = u.Save()
		if err != nil {
			return nil, err
		} else {
			return u, nil
		}
	}
	return nil, errors.New("invalid invitation")
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fmt.Fprintf(w, mkHtml(LoginForm))
		return
	}

	if r.Method == "POST" {
		userName := r.FormValue("username")
		pw := r.FormValue("password")
		invitation := r.FormValue("invite")
		var u *User
		var err error
		if invitation != "" {
			u, err = acceptInvite(userName, pw, invitation)
			if err != nil {
				http.Error(w, "invitation error", http.StatusUnauthorized)
				return
			}
			u.setSession(w)
			http.Redirect(w, r, r.URL.Path, 302)
			return
		}

		err, u = LoginByName(userName, pw)
		if err != nil {
			http.Error(w, "invalid username/password", http.StatusUnauthorized)
			return
		}
		err = u.setSession(w)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		} else {
			http.Redirect(w, r, "/", 302)
			return
		}
	}
}
