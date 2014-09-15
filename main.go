package main

import (
	"./auth"
	"fmt"
	"net/http"
	"strconv"
)

func can(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello")
	return
}

func cant(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "shouldnt")
	return
}

func echoAdminInvite(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	admin := r.FormValue("admin") == "true"
	trust, _ := strconv.Atoi(r.FormValue("trust"))
	user, invitation, err := auth.NewUserInvitation(email, admin, trust)
	fmt.Println(user, invitation, err)
	fmt.Fprintf(w, invitation)
	return
}

func main() {
	//_ = auth.RotateActiveKeys()
	adminRule := &auth.Rule{Admin: true}
	http.Handle("/cant/", auth.Wrap(http.HandlerFunc(cant), adminRule))
	inviteRule := &auth.Rule{Trust: 5}
	http.Handle("/maybe/", auth.Wrap(http.HandlerFunc(cant), inviteRule))
	http.Handle("/", http.HandlerFunc(can))
	http.Handle("/secret", http.HandlerFunc(echoAdminInvite))
	http.ListenAndServe(":9090", nil)
}
