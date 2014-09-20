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
			return u, u.Save()
		}
	}
	return nil, errors.New("invalid invitation")
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		fmt.Fprintf(w, mkHtml(loginForm))
		return
	}

	if r.Method == "POST" {
		userName := r.FormValue("user_name")
		pw := r.FormValue("password")
		//pwc := r.FormValue("password_confirm")
		invitation := r.FormValue("invite")
		var u *User
		var err error
		if invitation != "" {
			u, err = acceptInvite(userName, pw, invitation)
			if err != nil {
				http.Error(w, "invitation error", http.StatusUnauthorized)
				return
			}
			fmt.Fprintf(w, "welcome")
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

	if r.Method == "DELETE" {
		u := &User{}
		u.overwriteSession(w)
		http.Redirect(w, r, "/", 302)
	}
}

func Signup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		fmt.Fprintf(w, mkHtml(loginForm))
		return
	case "POST":
		userName := r.FormValue("user_name")
		invitation := r.FormValue("invite")
		if userName == "" || invitation == "" {
			http.Redirect(w, r, "/", 302)
		}
		invite := decode(invitation)
		if invite == nil {
			http.Redirect(w, r, "/", 302)
			return
		}
		var u *User
		err := json.Unmarshal(invite, &u)
		if err != nil {
			http.Error(w, "expired or invalid invitation", http.StatusUnauthorized)
			return
		}
		password := r.FormValue("password")
		if password == "" {
			http.Redirect(w, r, "/", 302)
			return
		}
		err = u.Save()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		_ = u.setSession(w)
		http.Redirect(w, r, "/", 302)
		return
	}
}
