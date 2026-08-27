package socket

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"

	socketio "hpsserver/internal/socketio"
)

// core.NewServer opens the DB with driver name "sqlite", but the mattn driver
// registers itself as "sqlite3". Register "sqlite" so tests can open a DB.
func init() {
	sql.Register("sqlite", &sqlite3.SQLiteDriver{})
}

// TestSearchContractsTotalExcludesHiddenReplicatedContracts verifies the Bug #3 fix:
// handleSearchContracts must report `total` based only on contracts that actually
// pass ShouldHideReplicatedContract (i.e. NOT (username in custody/system AND verified=0)).
// Previously `total` used the raw SQL COUNT over the whole table, overcounting hidden
// contracts and making client-side pagination freeze.
func TestSearchContractsTotalExcludesHiddenReplicatedContracts(t *testing.T) {
	coreServer := newTestCoreServer(t)
	s := &Server{
		io:      socketio.NewServer(nil),
		server:  coreServer,
		clients: map[string]*ClientState{},
		conns:   map[string]socketio.Conn{},
	}

	conn := &testConn{id: "sid-browser"}
	s.clients[conn.id] = &ClientState{
		Authenticated: true,
		Username:      "alice",
		NodeType:      "client",
	}
	s.conns[conn.id] = conn

	nowTs := float64(time.Now().Unix())

	// 5 hidden replicated contracts: username custody/system and verified=0.
	for i := 0; i < 5; i++ {
		_, _ = coreServer.DB.Exec(`INSERT INTO contracts
			(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("hidden-%d", i), "upload_file", fmt.Sprintf("h%d", i), "", "custody", "sig", nowTs, 0, "Y29udGVudA==")
	}
	// 8 visible contracts.
	for i := 0; i < 8; i++ {
		_, _ = coreServer.DB.Exec(`INSERT INTO contracts
			(contract_id, action_type, content_hash, domain, username, signature, timestamp, verified, contract_content)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("visible-%d", i), "upload_file", fmt.Sprintf("v%d", i), "", "alice", "sig", nowTs, 1, "Y29udGVudA==")
	}

	conn.emitted = nil
	s.handleSearchContracts(conn, map[string]any{
		"search_type":  "",
		"search_value": "",
		"limit":        50,
		"offset":       0,
	})

	payload := findEvent(conn, "contracts_results")
	if payload == nil {
		t.Fatal("expected contracts_results event")
	}
	if success, _ := payload["success"].(bool); !success {
		t.Fatalf("expected success, got error=%v", payload["error"])
	}

	total, _ := payload["total"].(int)
	if total != 8 {
		t.Fatalf("expected total=8 (visible only), got %d", total)
	}

	contracts, ok := payload["contracts"].([]map[string]any)
	if !ok {
		if raw, ok2 := payload["contracts"].([]any); ok2 {
			if len(raw) != 8 {
				t.Fatalf("expected 8 returned contracts, got %d", len(raw))
			}
			for _, c := range raw {
				if cm, ok3 := c.(map[string]any); ok3 && asString(cm["username"]) == "custody" {
					t.Fatalf("hidden replicated contract leaked into results: %#v", cm)
				}
			}
			return
		}
		t.Fatalf("unexpected contracts type: %T", payload["contracts"])
	}
	if len(contracts) != 8 {
		t.Fatalf("expected 8 returned contracts, got %d", len(contracts))
	}
	for _, c := range contracts {
		if asString(c["username"]) == "custody" {
			t.Fatalf("hidden replicated contract leaked into results: %#v", c)
		}
	}
}
