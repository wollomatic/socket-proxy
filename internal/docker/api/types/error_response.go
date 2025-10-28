package types

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/api/types/error_response.go
*/

// ErrorResponse Represents an error.
// swagger:model ErrorResponse
type ErrorResponse struct {

	// The error message.
	// Required: true
	Message string `json:"message"`
}
