package main

import (
	"./auth"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
)

var (
	firstRun = flag.Bool("first_run", false, "print an initial admin invitation")
)

var adminRule = &auth.Rule{Admin: true}
var sharedByInvitation = &auth.Rule{Trust: 5}

var localCouchDB *httputil.ReverseProxy

func generallyPublic(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello")
	return
}

func cant(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "shouldnt")
	return
}

func printInvite(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	admin := r.FormValue("admin") == "true"
	trust, _ := strconv.Atoi(r.FormValue("trust"))
	_, invitation, err := auth.NewUserInvitation(email, admin, trust)
	if err != nil {
		http.Error(w, "unable to generate invitation", http.StatusInternalServerError)
		return
	}
	invite := make(map[string]string)
	invite["invitation"] = invitation
	bits, err := json.Marshal(&invitation)
	if err != nil {
		http.Error(w, "unable to generate invitation", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, string(bits))
	return
}

func dropAllKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method == "DELETE" {
		err := auth.ResetKeys()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "OK! All sessions and pending invitations cancelled.\n")
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func main() {
	//_ = auth.RotateActiveKeys()
	flag.Parse()
	err := auth.New()
	if err != nil {
		panic(err)
	}
	if *firstRun {
		// can only be run once, initial user name will be 'admin',
		// password set on invitation acceptance
		fmt.Println(auth.FirstRunInvitation())
	}
	http.Handle("/", http.HandlerFunc(generallyPublic))
	http.Handle("/cant/", auth.Wrap(http.HandlerFunc(cant), adminRule))
	http.Handle("/maybe/", auth.Wrap(http.HandlerFunc(cant), sharedByInvitation))
	http.Handle("/invites/", auth.Wrap(http.HandlerFunc(printInvite), adminRule))
	http.Handle("/private/", auth.Wrap(http.StripPrefix("/private",
		http.FileServer(http.Dir("./my-files"))),
		adminRule))
	couchUrl, err := url.Parse("http://localhost:5894")
	if err != nil {
		localCouchDB = httputil.NewSingleHostReverseProxy(couchUrl)
		http.Handle("/couchdb/", http.StripPrefix("/couchdb", localCouchDB))
	}
	http.ListenAndServe(":9090", nil)
}
