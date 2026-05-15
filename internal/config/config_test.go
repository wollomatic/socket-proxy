package config

import (
	"flag"
	"math"
	"os"
	"reflect"
	"regexp"
	"sort"
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
			got, got2, _, gotErr := extractLabelData(tt.cntr)
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
		aRegexStrings := make([]string, 0, len(aRegexes))
		for _, ar := range aRegexes {
			aRegexStrings = append(aRegexStrings, ar.String())
		}
		bRegexStrings := make([]string, 0, len(bRegexes))
		for _, br := range bRegexes {
			bRegexStrings = append(bRegexStrings, br.String())
		}
		sort.Strings(aRegexStrings)
		sort.Strings(bRegexStrings)
		for i, ar := range aRegexStrings {
			if ar != bRegexStrings[i] {
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

func TestInitConfig_DenyHostConfigFlags(t *testing.T) {
	restore := resetFlagsForTest(t, []string{
		"socket-proxy",
		"-denyprivileged",
		"-denycapadd",
		"-denyhostnamespaces",
	})
	defer restore()

	cfg, err := InitConfig()
	if err != nil {
		t.Fatalf("InitConfig() error = %v", err)
	}
	if !cfg.AllowLists.Default.DenyPrivileged {
		t.Error("expected DenyPrivileged=true")
	}
	if !cfg.AllowLists.Default.DenyCapAdd {
		t.Error("expected DenyCapAdd=true")
	}
	if !cfg.AllowLists.Default.DenyHostNamespaces {
		t.Error("expected DenyHostNamespaces=true")
	}
}

func TestInitConfig_DenyHostConfigEnvVars(t *testing.T) {
	t.Setenv("SP_DENYPRIVILEGED", "true")
	t.Setenv("SP_DENYCAPADD", "1")
	t.Setenv("SP_DENYHOSTNAMESPACES", "TRUE")
	restore := resetFlagsForTest(t, []string{"socket-proxy"})
	defer restore()

	cfg, err := InitConfig()
	if err != nil {
		t.Fatalf("InitConfig() error = %v", err)
	}
	if !cfg.AllowLists.Default.DenyPrivileged {
		t.Error("expected DenyPrivileged=true via env")
	}
	if !cfg.AllowLists.Default.DenyCapAdd {
		t.Error("expected DenyCapAdd=true via env")
	}
	if !cfg.AllowLists.Default.DenyHostNamespaces {
		t.Error("expected DenyHostNamespaces=true via env")
	}
}

func TestInitConfig_DenyHostConfigDefaultsFalse(t *testing.T) {
	restore := resetFlagsForTest(t, []string{"socket-proxy"})
	defer restore()

	cfg, err := InitConfig()
	if err != nil {
		t.Fatalf("InitConfig() error = %v", err)
	}
	if cfg.AllowLists.Default.DenyPrivileged {
		t.Error("expected DenyPrivileged=false by default")
	}
	if cfg.AllowLists.Default.DenyCapAdd {
		t.Error("expected DenyCapAdd=false by default")
	}
	if cfg.AllowLists.Default.DenyHostNamespaces {
		t.Error("expected DenyHostNamespaces=false by default")
	}
}

func Test_extractLabelData_DenyLabels(t *testing.T) {
	tests := []struct {
		name    string
		labels  map[string]string
		want    denyLabels
		wantErr bool
	}{
		{
			name:   "no deny labels",
			labels: map[string]string{"socket-proxy.allow.get": "/.*"},
			want:   denyLabels{},
		},
		{
			name: "deny privileged true",
			labels: map[string]string{
				"socket-proxy.deny.privileged": "true",
			},
			want: denyLabels{Privileged: true},
		},
		{
			name: "deny capadd 1",
			labels: map[string]string{
				"socket-proxy.deny.capadd": "1",
			},
			want: denyLabels{CapAdd: true},
		},
		{
			name: "deny hostnamespaces true",
			labels: map[string]string{
				"socket-proxy.deny.hostnamespaces": "TRUE",
			},
			want: denyLabels{HostNamespaces: true},
		},
		{
			name: "all deny labels",
			labels: map[string]string{
				"socket-proxy.deny.privileged":     "true",
				"socket-proxy.deny.capadd":         "true",
				"socket-proxy.deny.hostnamespaces": "true",
			},
			want: denyLabels{Privileged: true, CapAdd: true, HostNamespaces: true},
		},
		{
			name: "deny false is treated as not set",
			labels: map[string]string{
				"socket-proxy.deny.privileged": "false",
			},
			want: denyLabels{},
		},
		{
			name: "invalid deny value returns error",
			labels: map[string]string{
				"socket-proxy.deny.privileged": "yes",
			},
			wantErr: true,
		},
		{
			name: "unknown deny key ignored",
			labels: map[string]string{
				"socket-proxy.deny.unknown": "true",
			},
			want: denyLabels{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, got, gotErr := extractLabelData(container.Summary{Labels: tt.labels})
			if tt.wantErr {
				if gotErr == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("unexpected error: %v", gotErr)
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDenyLabelsAny(t *testing.T) {
	if (denyLabels{}).any() {
		t.Error("empty denyLabels should not be any()")
	}
	if !(denyLabels{Privileged: true}).any() {
		t.Error("denyLabels{Privileged} should be any()")
	}
	if !(denyLabels{CapAdd: true}).any() {
		t.Error("denyLabels{CapAdd} should be any()")
	}
	if !(denyLabels{HostNamespaces: true}).any() {
		t.Error("denyLabels{HostNamespaces} should be any()")
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
