package container

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/api/types/container/container.go
*/

// Summary contains response of Engine API:
// GET "/containers/json"
type Summary struct {
	ID              string `json:"Id"`
	Names           []string
	Labels          map[string]string
	NetworkSettings *NetworkSettingsSummary
}
