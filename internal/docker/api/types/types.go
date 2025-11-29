package types

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/api/types/types.go
*/

// Ping contains response of Engine API:
// GET "/_ping"
type Ping struct {
	APIVersion string
}
