package oob

import (
	"net/http"
	"testing"
	"time"
)

func TestInteractorRecordsCallback(t *testing.T) {
	it, err := NewInteractor("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	token, url := it.NewSession()
	if len(it.Poll(token)) != 0 {
		t.Fatal("no interaction expected before callback")
	}
	resp, err := http.Get("http://" + url + "/probe")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(it.Poll(token)) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	hits := it.Poll(token)
	if len(hits) != 1 || hits[0].Protocol != "http" {
		t.Fatalf("callback must be recorded as http interaction, got %+v", hits)
	}
}

func TestInteractorIgnoresUnknownToken(t *testing.T) {
	it, err := NewInteractor("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	resp, err := http.Get("http://" + it.Host() + "/not-a-valid-token")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	token, _ := it.NewSession()
	if len(it.Poll(token)) != 0 {
		t.Fatal("unknown token must not record interactions for a fresh session")
	}
}
