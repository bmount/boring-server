package auth

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/fernet/fernet-go"
	"os"
	"os/exec"
	"testing"
)

var (
	testDataDir           = flag.String("test_data_dir", "./test/data-dir", "test data dir")
	testFirstRun          = flag.Bool("test_first_run", true, "test first run")
	forceDeleteNonDefault = flag.Bool("force_delete_non_default", false, "delete non-default test data dir on test reruns")
)

func init() {
	if *forceDeleteNonDefault || *testDataDir == "./test/data-dir" {
		os.RemoveAll(*testDataDir)
	}
	err := NewWithOpts(Opts{
		DBName:     "test.db",
		CookieName: "testtest",
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
		fmt.Errorf("Initializatoin error: Root user invitation not generated: %v\n", err)
		panic(err)
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

}

func TestKeyCount(t *testing.T) {
	if len(activeKeys) < numberOfKeys {
		t.Errorf("keys failed to load")
	}
}

func TestInvitations(t *testing.T) {
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

func TestUserSequence(t *testing.T) {
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
