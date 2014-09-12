package auth

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/json"
	"errors"
	"fmt"
	seq "github.com/streadway/simpleuuid"
	"net/http"
	"time"
)

type User struct {
	EncryptedPassword string    `json:-`
	Uuid              seq.UUID  `json:uuid`
	UniqueName        string    `json:name`
	Email             string    `json:-`
	Admin             bool      `json:adm`
	Trust             int       `json:trust`
	Active            bool      `json:-`
	LastSeen          time.Time `json:-`
}

func (u *User) invite() {

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

func getSession(r *http.Request) (loggedIn, admin bool, u *User) {
	cookie, err := r.Cookie(*cookieName)
	if err != nil {
		return
	}
	msg := decode(cookie.Value)
	if msg == nil {
		return
	}
	err = json.Unmarshal(msg, &u)
	if err != nil {
		u = nil
		return
	}
	return true, u.Admin, u
}

func (u *User) setSession(w http.ResponseWriter) (err error) {
	cookie, err := u.Cookie()
	if err != nil {
		return
	}
	http.SetCookie(w, cookie)
	return
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

func (u *User) Save() (err error) {
	db := Db()
	defer db.Close()
	if db == nil {
		err = errors.New("no db")
		return
	}
	return
}

func GetUser(identifier, where string) (*User, error) {
	var clause string
	switch identifier {
	case "email":
		clause = " where email = $1"
	case "id":
		clause = " where id = ?"
	default:
		return nil, errors.New("invalid identifier")
	}
	db := Db()
	defer db.Close()
	user := &User{}
	err := db.QueryRow(`query`).Scan(&user)
	fmt.Println(BaseQuery()+" "+clause+" "+where, user, err)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func BaseQuery() (bq string) {
	bq = `select ... `
	return
}

func LoginByEmail(email, givenPw string) (authed error, u *User) {
	u, err := GetUser("email", email)
	if err != nil {
		authed = err
		return
	}
	authed = bcrypt.CompareHashAndPassword([]byte(u.EncryptedPassword), []byte(givenPw))
	if authed != nil {
		u = nil
		return
	} else {
		return nil, u
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		err := templates.ExecuteTemplate(w, "login_form.tmpl", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	if r.Method == "POST" {
		chosenName := r.FormValue("chosen_name")
		pw := r.FormValue("password")
		authFail, u := LoginByEmail(chosenName, pw)
		if authFail != nil {
			fmt.Println(authFail)
			http.Redirect(w, r, "/failed-password", 307)
			return
		} else {
			cookie, err := u.genCookie()
			if err != nil {
				fmt.Println(err)
				http.Redirect(w, r, "/failed-session-create", 307)
				return
			} else {
				http.SetCookie(w, cookie)
				session, _ := store.Get(r, "amalia")
				session.Options.MaxAge = 100000000
				session.Values["user"] = u
				session.Save(r, w)
				http.Redirect(w, r, "/", 302)
				return
			}
		}
	}

	if r.Method == "DELETE" {
		session, err := store.Get(r, "amalia")
		defer http.Redirect(w, r, "/", 302)
		if err != nil {
			fmt.Println(err)
		} else {
			session.Options.MaxAge = -1
			if err := session.Save(r, w); err != nil {
				fmt.Println("Error saving session: %v", err)
			}
		}
	}
}

func Signup(w http.ResponseWriter, r *http.Request) {
	//q := r.URL.Query()
	switch r.Method {
	case "GET":
		_ = templates.ExecuteTemplate(w, "sign_up.tmpl", nil)
	case "POST":
		chosenName := r.FormValue("chosen_name")
		if chosenName == "" {
			http.Redirect(w, r, "/", 302)
			return
		}
		password := r.FormValue("password")
		if password == "" {
			http.Redirect(w, r, "/", 302)
			fmt.Println("no password:", password)
			return
		}
		db := Db()
		defer db.Close()
		u, err := NewUser(chosenName, password)
		if err != nil {
			http.Redirect(w, r, "/", 302)
			fmt.Println("err new user: ", chosenName, password)
			return
		}
		u.Save()
		u.CreateSession(w, r)
		http.Redirect(w, r, "/", 302)
		return
	}
}
