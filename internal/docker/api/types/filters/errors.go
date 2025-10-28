package filters

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/api/types/filters/errors.go
*/

import "fmt"

// invalidFilter indicates that the provided filter or its value is invalid
type invalidFilter struct {
	Filter string
	Value  []string
}

func (e invalidFilter) Error() string {
	msg := "invalid filter"
	if e.Filter != "" {
		msg += " '" + e.Filter
		if e.Value != nil {
			msg = fmt.Sprintf("%s=%s", msg, e.Value)
		}
		msg += "'"
	}
	return msg
}

// InvalidParameter marks this error as ErrInvalidParameter
func (e invalidFilter) InvalidParameter() {}
