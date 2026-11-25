// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newTestKey(t *testing.T) (authorized string, blob []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), key.Marshal()
}

// Stored values in proxy-prod-users are often wrapped in quotes/whitespace.
func TestParseKeyItem(t *testing.T) {
	authorized, blob := newTestKey(t)
	for _, pub := range []string{authorized, `"` + authorized + `"`, "  \"" + authorized + " some comment\"\n"} {
		got, user, ok := parseKeyItem(pub, " 0005510CFEF3 ")
		if !ok || got != string(blob) || user != "0005510CFEF3" {
			t.Fatalf("parseKeyItem(%q) = ok=%v user=%q, blob match=%v", pub, ok, user, got == string(blob))
		}
	}
	for _, tc := range [][2]string{{"", "mac"}, {authorized, ""}, {"not a key", "mac"}} {
		if _, _, ok := parseKeyItem(tc[0], tc[1]); ok {
			t.Fatalf("parseKeyItem(%q, %q) accepted invalid input", tc[0], tc[1])
		}
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAuthorizedKeysDynamoLookupAndMissRefresh(t *testing.T) {
	_, known := newTestKey(t)
	_, added := newTestKey(t)

	var scans atomic.Int32
	var includeAdded atomic.Bool
	scan := func(context.Context) (map[string]string, error) {
		// First scan fails: frps must keep retrying instead of giving up.
		if scans.Add(1) == 1 {
			return nil, errors.New("dynamodb unreachable")
		}
		keys := map[string]string{string(known): "known-mac"}
		if includeAdded.Load() {
			keys[string(added)] = "added-mac"
		}
		return keys, nil
	}

	// Long timer so only startup retry and miss refreshes cause scans.
	a := newAuthorizedKeysDynamo(scan, time.Hour, 50*time.Millisecond)
	defer a.Close()

	// Startup backoff is 5s; a miss refresh loads the keys sooner.
	waitFor(t, func() bool {
		user, ok, _ := a.LookupUser(context.Background(), known)
		return ok && user == "known-mac"
	})

	// A key registered after the last load is picked up by a miss refresh.
	includeAdded.Store(true)
	if _, ok, _ := a.LookupUser(context.Background(), added); ok {
		t.Fatal("added key found before reload")
	}
	waitFor(t, func() bool {
		_, ok, _ := a.LookupUser(context.Background(), added)
		return ok
	})

	// Misses inside the window must not trigger more scans.
	before := scans.Load()
	a.lastMissRefresh.Store(time.Now().UnixNano())
	a.missInterval = time.Hour
	for range 100 {
		_, _, _ = a.LookupUser(context.Background(), []byte("unknown"))
	}
	time.Sleep(50 * time.Millisecond)
	if got := scans.Load(); got != before {
		t.Fatalf("misses inside the window triggered %d extra scans", got-before)
	}
}
