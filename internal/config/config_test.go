package config

import (
	"flag"
	"math"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"testing"

	"github.com/wollomatic/socket-proxy/internal/docker/api/types/container"
)

func resetFlagsForTest(t *testing.T, args []string) func() {
	t.Helper()

	prevCommandLine := flag.CommandLine
	prevArgs := os.Args

	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	os.Args = args

	return func() {
		flag.CommandLine = prevCommandLine
		os.Args = prevArgs
	}
}

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
			if !regexMapsEqual(got, tt.want) {
				t.Errorf("extractLabelData() = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("extractLabelData() = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func regexMapsEqual(a, b map[string][]*regexp.Regexp) bool {
	if len(a) != len(b) {
		return false
	}
	for method, aRegexes := range a {
		bRegexes, ok := b[method]
		if !ok || len(aRegexes) != len(bRegexes) {
			return false
		}
		for i, ar := range aRegexes {
			if ar.String() != bRegexes[i].String() {
				return false
			}
		}
	}
	return true
}

func TestInitConfig_AllowMethodFlagOverridesEnv(t *testing.T) {
	t.Setenv("SP_ALLOW_GET", "/from-env")
	restore := resetFlagsForTest(t, []string{"socket-proxy", "-allowGET=/from-flag"})
	defer restore()

	cfg, err := InitConfig()
	if err != nil {
		t.Fatalf("InitConfig() error = %v", err)
	}

	regexes := cfg.AllowLists.Default.AllowedRequests["GET"]
	if len(regexes) != 1 {
		t.Fatalf("expected 1 GET regex, got %d", len(regexes))
	}
	if !regexes[0].MatchString("/from-flag") {
		t.Fatalf("expected GET regex to match /from-flag, got %q", regexes[0].String())
	}
	if regexes[0].MatchString("/from-env") {
		t.Fatalf("expected env GET regex to be ignored when flag is present, got %q", regexes[0].String())
	}
}

func TestInitConfig_ShutdownGraceTimeTooLarge(t *testing.T) {
	restore := resetFlagsForTest(t, []string{
		"socket-proxy",
		"-shutdowngracetime=" + strconv.FormatUint(uint64(math.MaxInt)+1, 10),
	})
	defer restore()

	_, err := InitConfig()
	if err == nil {
		t.Fatal("InitConfig() unexpectedly succeeded")
	}
}

func TestInitConfig_WatchdogIntervalTooLarge(t *testing.T) {
	restore := resetFlagsForTest(t, []string{
		"socket-proxy",
		"-watchdoginterval=" + strconv.FormatUint(uint64(math.MaxInt)+1, 10),
	})
	defer restore()

	_, err := InitConfig()
	if err == nil {
		t.Fatal("InitConfig() unexpectedly succeeded")
	}
}
