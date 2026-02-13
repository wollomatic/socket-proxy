package config

import (
	"flag"
	"strings"
)

type from int

const (
	fromEnv   from = 1
	fromParam from = 2
)

type param struct {
	value string
	from  from
}

type arrayParams []param

// ensure that arrayParams implements the flag.Value interface
var _ flag.Value = (*arrayParams)(nil)

func (a *arrayParams) String() string {
	var values []string
	for _, p := range *a {
		values = append(values, p.value)
	}
	return strings.Join(values, ", ")
}

func (a *arrayParams) Set(value string) error {
	*a = append(*a, param{value: value, from: fromParam})
	return nil
}
