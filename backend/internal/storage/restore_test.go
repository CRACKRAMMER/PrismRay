// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"path/filepath"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
)

func TestRestorePersistsBothCollectionsAndLaterEdits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prismray.db")
	s, e := NewStore(path)
	if e != nil {
		t.Fatal(e)
	}
	n := &config.Node{ID: "n", Protocol: config.ProtocolTrojan, Address: "example.com", Port: 443, Password: "secret"}
	l := &config.ListenConfig{ID: "l", Protocol: "mixed", Address: "127.0.0.1", Port: 10808, NodeIDs: []string{"n"}}
	if e = s.Restore([]*config.Node{n}, []*config.ListenConfig{l}); e != nil {
		t.Fatal(e)
	}
	n.Name = "edited"
	if e = s.Update(n); e != nil {
		t.Fatal(e)
	}
	_ = s.Close()
	s, e = NewStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.Get("n").Name != "edited" || len(s.ListListeners()) != 1 {
		t.Fatal("restore/edit lost data")
	}
	if e = s.Restore(nil, []*config.ListenConfig{l}); e == nil {
		t.Fatal("accepted dangling reference")
	}
	if s.Get("n") == nil {
		t.Fatal("invalid restore changed state")
	}
}
