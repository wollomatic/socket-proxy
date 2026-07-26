package config

import (
	"flag"
	"math"
	"os"
	"strconv"
	"testing"
)

func resetFlagsForTest(t *testing.T, args []string) func() {
	t.Helper()

	prevCommandLine := flag.CommandLine
	prevArgs := os.Args
	prevDockerLabelPrefix := allowedDockerLabelPrefix

	flag.CommandLine = flag.NewFlagSet(args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)
	os.Args = args

	return func() {
		flag.CommandLine = prevCommandLine
		os.Args = prevArgs
		allowedDockerLabelPrefix = prevDockerLabelPrefix
	}
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

func TestInitConfig_DockerLabelPrefixFlagOverridesEnv(t *testing.T) {
	t.Setenv("SP_DOCKERLABELPREFIX", "from-env")
	restore := resetFlagsForTest(t, []string{"socket-proxy", "-dockerlabelprefix=gameserver-socket-proxy"})
	defer restore()

	_, err := InitConfig()
	if err != nil {
		t.Fatalf("InitConfig() error = %v", err)
	}

	if got, want := allowedDockerLabelPrefix, "gameserver-socket-proxy.allow."; got != want {
		t.Errorf("allowedDockerLabelPrefix = %q, want %q", got, want)
	}
}

func TestInitConfig_InvalidDockerLabelPrefix(t *testing.T) {
	for _, prefix := range []string{
		"Traefik",
		"traefik..proxy",
		"traefik-",
	} {
		t.Run(prefix, func(t *testing.T) {
			restore := resetFlagsForTest(t, []string{"socket-proxy", "-dockerlabelprefix=" + prefix})
			defer restore()

			if _, err := InitConfig(); err == nil {
				t.Fatalf("InitConfig() with dockerlabelprefix %q unexpectedly succeeded", prefix)
			}
		})
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
