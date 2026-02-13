package config

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/wollomatic/socket-proxy/internal/docker/api/types/container"
)

func Test_extractLabelData(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		cntr    container.Summary
		want    map[string][]*regexp.Regexp
		want2   []string
		wantErr bool
	}{
		{
			name: "valid labels with multiple methods and regexes",
			cntr: container.Summary{
				Labels: map[string]string{
					"socket-proxy.allow.get.0": "regex1",
					"socket-proxy.allow.get.1": "regex2",
					"socket-proxy.allow.post":  "regex3",
				},
			},
			want: map[string][]*regexp.Regexp{
				"GET":  {regexp.MustCompile("^regex1$"), regexp.MustCompile("^regex2$")},
				"POST": {regexp.MustCompile("^regex3$")},
			},
			want2:   nil,
			wantErr: false,
		},
		{
			name: "invalid regex in label value",
			cntr: container.Summary{
				Labels: map[string]string{
					"socket-proxy.allow.get": "invalid[regex",
				},
			},
			want:    nil,
			want2:   nil,
			wantErr: true,
		},
		{
			name: "non-allow labels are ignored",
			cntr: container.Summary{
				Labels: map[string]string{
					"socket-proxy.allow.get": "regex1",
					"other.label":            "value",
				},
			},
			want: map[string][]*regexp.Regexp{
				"GET": {regexp.MustCompile("^regex1$")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got2, gotErr := extractLabelData(tt.cntr)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("extractLabelData() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("extractLabelData() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractLabelData() = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("extractLabelData() = %v, want %v", got2, tt.want2)
			}
		})
	}
}
