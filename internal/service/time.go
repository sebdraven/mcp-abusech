package service

import "time"

// now stamps every answer with when it was fetched.
//
// This matters more here than it would elsewhere. The galaxy server answers
// from a corpus pinned to a commit, so a result can be reproduced exactly;
// abuse.ch is a live service, and the same query tomorrow may return more,
// fewer or differently-classified samples. The timestamp is the only
// provenance available, so it travels with every result rather than being
// left for the caller to remember.
func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
