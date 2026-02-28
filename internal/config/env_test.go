package config

import (
	"reflect"
	"testing"
)

func Test_getAllowFromEnv(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		env  []string
		want map[string][]string
	}{
		{
			name: "single method",
			env:  []string{"SP_ALLOW_GET=/allowed/path"},
			want: map[string][]string{"GET": {"/allowed/path"}},
		},
		{
			name: "multiple methods",
			env:  []string{"SP_ALLOW_GET=/get/path", "SP_ALLOW_POST=/post/path"},
			want: map[string][]string{"GET": {"/get/path"}, "POST": {"/post/path"}},
		},
		{
			name: "multiple entries for one method",
			env:  []string{"SP_ALLOW_GET=/path/one", "SP_ALLOW_GET_1=/path/two"},
			want: map[string][]string{"GET": {"/path/one", "/path/two"}},
		},
		{
			name: "multiple entries for one method with non-sequential index",
			env:  []string{"SP_ALLOW_GET=/path/one", "SP_ALLOW_GET_2=/path/two"},
			want: map[string][]string{"GET": {"/path/one", "/path/two"}},
		},
		{
			name: "no relevant env vars",
			env:  []string{"OTHER_ENV=some_value"},
			want: map[string][]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getAllowFromEnv(tt.env)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getAllowFromEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}
