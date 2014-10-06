package auth

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fernet/fernet-go"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"testing"
)

var (
	testDataDir           = flag.String("test_data_dir", "./test/data-dir", "test data dir")
	testFirstRun          = flag.Bool("test_first_run", true, "test first run")
	forceDeleteNonDefault = flag.Bool("force_delete_non_default", false, "delete non-default test data dir on test reruns")
)

var testCookieName string = "testtest"

func init() {
	if *forceDeleteNonDefault || *testDataDir == "./test/data-dir" {
		os.RemoveAll(*testDataDir)
	}
	err := NewWithOpts(Opts{
		DBName:     "test.db",
		CookieName: testCookieName,
		DataDir:    *testDataDir,
	})
	if err != nil {
		panic(err)
	}
	firstRunTest()
}

func firstRunTest() {
	u, invite, err := FirstRunInvitation("admin")
	if u == nil {
		fmt.Errorf("Initialization error: Root user creation error: %v", err)
		panic(err)
	}
	if invite == "" {
		fmt.Errorf("Initialization error: Root user invitation not generated: %v", err)
		panic(err)
	}
	retryUser, retryInvitationString, retryErr := FirstRunInvitation("admin")
	if retryErr == nil || retryUser != nil || retryInvitationString != "" {
		fmt.Errorf("First run invitaition may be run at most once")
		panic("more than one initial admin user created")
	}
}

func TestKeyRotation(t *testing.T) {
	initiallyActive := make(map[*fernet.Key]bool)
	for _, val := range activeKeys {
		initiallyActive[val] = true
	}
	err := RotateActiveKeys()
	if err != nil {
		t.Error(err)
	}
	shouldHave := len(activeKeys) - 1
	doesHave := 0
	for _, val := range activeKeys {
		_, ok := initiallyActive[val]
		if ok {
			doesHave++
		}
	}
	if doesHave != shouldHave {
		t.Errorf("Expected %v old keys to remain, got %v\n", shouldHave, doesHave)
	}
	err = ResetKeys()
	if err != nil {
		t.Error(err)
	}
	shouldHave = 0
	doesHave = 0
	for _, val := range activeKeys {
		_, ok := initiallyActive[val]
		if ok {
			doesHave++
		}
	}
	if doesHave != shouldHave {
		t.Errorf("Expected 0 old keys to remain, got %v\n", doesHave)
	}
	clonedKeysPostReset := make(map[*fernet.Key]bool)
	for _, k := range activeKeys {
		clonedKeysPostReset[k] = true
	}
	numberOfKeys = numberOfKeys * 2
	// Key rotation on change in key number should cycle all
	err = RotateActiveKeys()
	if err != nil {
		t.Errorf("error in second key rotation: %v\n", err)
	}
	for _, k := range activeKeys {
		if clonedKeysPostReset[k] {
			t.Errorf("Rotating after key count change failed to reset all")
		}
	}
}

func TestLoadKeys(t *testing.T) {
	// this is tested indirectly in init, simply:
	keys, err := loadKeys()
	if err != nil {
		t.Error(err)
	}
	if len(keys) != numberOfKeys {
		t.Errorf("Load keys failed to retrieve expected number")
	}
}

func TestKeyCount(t *testing.T) {
	if len(activeKeys) < numberOfKeys {
		t.Errorf("keys failed to load")
	}
}

func TestUserSequence(t *testing.T) {
	_, invitation, err := NewUserInvitation("bvmount@gmail.com", true, 1000)
	if err != nil {
		t.Error(err)
	}
	u, err := acceptInvite("bmount", "s3kr3t", invitation)
	if err != nil {
		t.Error(err)
	}
	if u == nil {
		t.Errorf("No user created on invite acceptance")
	}

	_, err = acceptInvite("bmount", "super-secret", invitation)
	if err == nil {
		t.Errorf("Invite cannot be re-accpeted")
	}
	_, err = acceptInvite("changed-bmounts-name", "super-secret-squared", invitation)
	if err == nil {
		t.Errorf("Invite not independent of chosen name")
	}

	successMsg := "ENTERED\n"
	privateSuccessMsg := "PRIVATE ENTERED\n"
	semiPrivateSuccessMsg := "SEMI PRIVATE ENTERED\n"

	var testMux *http.ServeMux = http.NewServeMux()

	var protectedEndpoint = Wrap(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, privateSuccessMsg)
			return
		}), &Rule{Admin: true})

	var semiProtectedEndpoint = Wrap(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, semiPrivateSuccessMsg)
			return
		}), &Rule{TrustExactly: 2})

	var unProtectedEndpoint = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, successMsg)
			return
		})

	testMux.Handle("/any/", protectedEndpoint)
	testMux.Handle("/semiprotected/", semiProtectedEndpoint)
	testMux.Handle("/", unProtectedEndpoint)
	testMux.Handle("/logout/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "DELETE" {
			u := &User{}
			u.OverwriteSession(w)
			return
		}
	}))

	ts := httptest.NewServer(testMux)
	defer ts.Close()

	baseUrl := ts.URL

	// test valid responses to unauthenticated user:
	res, err := http.Get(baseUrl + "/any/thing")
	if err != nil || res.StatusCode != 200 {
		t.Errorf("failed to load login page to unauthenticated user")
	}
	// if this isn't the login page, this test will eventually fail
	shouldBeLoginPage, _ := ioutil.ReadAll(res.Body)
	res, err = http.Get(baseUrl + "/unprotected/thing")
	if err != nil {
		t.Error(err)
		return
	}
	body, _ := ioutil.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != successMsg {
		t.Errorf("failed to load normal unprotected page to unauthenticated user")
	}

	// test login and serving of auth-wrapped urls to admins:
	testCookieJar, _ := cookiejar.New(nil)
	creds := url.Values{"username": {"bmount"}, "password": {"s3kr3t"}}
	cli := http.Client{
		Jar: testCookieJar,
	}
	req, err := http.NewRequest("POST", baseUrl+"/any/thing", bytes.NewBufferString(creds.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err = cli.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	if res.StatusCode != 200 {
		t.Errorf("A valid username/pass was not accepted")
	}
	res, err = cli.Get(baseUrl + "/any/thing/authenticated")
	body, _ = ioutil.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != privateSuccessMsg {
		t.Errorf("A post-login authenticated request was rejected in error")
	}

	// test access to a particular trust level and login page use of
	// invitation tokens
	limitedUser, invitation, _ := NewUserInvitation("limited @ pretend email", false, 2)
	semiProtectedCookieJar, _ := cookiejar.New(nil)
	creds = url.Values{"username": {"limited"}, "password": {"p4ssw0rd"}, "invite": {invitation}}
	cli = http.Client{
		Jar: semiProtectedCookieJar,
	}
	req, err = http.NewRequest("POST", baseUrl+"/semiprotected/thing", bytes.NewBufferString(creds.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	res, err = cli.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	if res.StatusCode != 200 {
		t.Errorf("A valid semiprotected username/pass was not accepted")
	}
	res, err = cli.Get(baseUrl + "/semiprotected/thing/authenticated")
	body, _ = ioutil.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != semiPrivateSuccessMsg {
		t.Errorf("A post-login semi-protected authenticated request was rejected in error")
	}

	limitedUser, _ = limitedUser.Load()
	err = limitedUser.ChangeName("unlimited-user")
	if err != nil {
		t.Error(err)
	}

	res, err = cli.Post(baseUrl+"/logout/", "", nil)
	if err != nil {
		t.Error(err)
		return
	}
	res, err = cli.Get(baseUrl + "/semiprotected/thing/authenticated")
	body, _ = ioutil.ReadAll(res.Body)
	// this should be equal to the default view of a non-logged-in user:
	if string(body) != string(shouldBeLoginPage) {
		t.Errorf("Cookie retained past overwrite request")
	}

	// test invalid login:
	res, err = http.PostForm(baseUrl+"/any/thing", url.Values{"username": {"changed-bmounts-name"}, "password": {"super-secret-squared"}})
	if res == nil {
		t.Error(err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("The invalid change was accepted/ unauthorized invite")
	}

	err = limitedUser.ChangeName("bmount")
	if err.Error() != "name unavailable" {
		t.Error(err)
	}
}

func TestTokenCompatibility(t *testing.T) {
	_, invitation, _ := NewUserInvitation("test-token", false, 0)
	userIn, err := acceptInvite("test-token-user", "test-token-unencrypted-password", invitation)
	if err != nil {
		t.Error(err)
		return
	}
	encoded, err := encode(userIn)
	if err != nil {
		t.Error(err)
		return
	}
	firstKey := activeKeys[0].Encode()
	pyEval := "from cryptography.fernet import Fernet; f = Fernet(b'"
	pyEval += firstKey + "'); print f.decrypt(b'" + encoded + "')"
	cmd := exec.Command("python", "-c", pyEval)
	out, err := cmd.Output()
	if err != nil {
		fmt.Printf(`
		Python and the 'cryptography' library are required
		to run tests. There is no original/DIY cryptographic
		anything going on here, just a check that the tokens
		used in cookies are compatible with multiple implementations
		of the Fernet spec https://github.com/fernet/spec
		`)
		t.Error(err)
	}
	userRoundTrip := &User{}
	if err = json.Unmarshal(out, &userRoundTrip); err != nil {
		t.Error(err)
	}
	if userIn.UniqueName != userRoundTrip.UniqueName {
		t.Error("roundtrip mismatch: unique name")
	}
	if userIn.Uuid != userRoundTrip.Uuid {
		t.Error("roundtrip mismatch: uuid")
	}
}

func TestUserLoad(t *testing.T) {
	u1, err := NewUser("欢 欢", "s3kr3t", false, 0)
	if err != nil {
		t.Errorf("Error on user u1: ", err)
	}
	// nameless users should not load
	_, expectedLoadError := u1.Load()
	if expectedLoadError == nil {
		t.Error(expectedLoadError)
	}
	u1.UniqueName = "欢 欢"
	err = u1.Save()
	if err != nil {
		t.Error(err)
	}
}
