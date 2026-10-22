package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Fix    string `json:"fix,omitempty"`
}

var envKeyRe = regexp.MustCompile(`(?i)(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=`)

// clientChecks are the health checks that look at the user's side: files,
// environment, wiring, the watcher, the AWS CLI and the clock.
func clientChecks(b Backend, sd *StatusData) []Check {
	var cs []Check
	if b.Mode() == ModeService {
		cs = append(cs, Check{"zsp service", true, "running; vault in %ProgramData%, sessions in service memory", ""})
		cs = append(cs, Check{"Enrolled with the service", sd.Enrolled, "Windows Hello key registered", "zsp setup"})
		cs = append(cs, Check{"Service key", sd.Backend == "tpm", "broker key backend: " + sd.Backend, "TPM unavailable to the service account; see docs/DESIGN.md"})
		if n := userModeLeftovers(); n > 0 {
			cs = append(cs, Check{"User-mode vault retired", false, fmt.Sprintf("%d key(s) still sealed in the old user-mode vault", n), "zsp service migrate"})
		}
	} else {
		cs = append(cs, platformHealth()...)
	}
	cs = append(cs, helloCheck())

	// Plaintext keys left in ~/.aws.
	found, _ := findPlaintextKeys()
	var stray, kept []string
	for _, k := range found {
		if sd.Settings.isKept(k.Profile) {
			kept = append(kept, k.Profile)
		} else {
			stray = append(stray, k.Profile+" ("+k.File+")")
		}
	}
	d := "none"
	if len(stray) > 0 {
		d = strings.Join(stray, ", ")
	}
	if len(kept) > 0 {
		d += "; left in plain text by choice: " + strings.Join(kept, ", ")
	}
	cs = append(cs, Check{"No plaintext keys in ~/.aws", len(stray) == 0, d, "zsp import"})

	// Keys in environment variables / shell profiles.
	var env []string
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		env = append(env, "AWS_ACCESS_KEY_ID (this shell)")
	}
	env = append(env, userEnvKeys()...)
	for _, f := range shellProfileFiles() {
		if b, err := os.ReadFile(f); err == nil && envKeyRe.Match(b) {
			env = append(env, f)
		}
	}
	d = "none"
	if len(env) > 0 {
		d = strings.Join(env, ", ") + " — the AWS CLI prefers these to any profile, so the vault is bypassed"
	}
	cs = append(cs, Check{"No keys in environment or shell profiles", len(env) == 0, d, "remove the variables, then `zsp import`"})

	// Wiring.
	wired := wiredProfiles()
	var bad []string
	for _, p := range sd.Profiles {
		if !wiredToZsp(wired[p.Name]) {
			bad = append(bad, p.Name)
		}
		if p.Policy.WriteProfile != "" && !wiredToZsp(wired[p.Policy.WriteProfile]) {
			bad = append(bad, p.Policy.WriteProfile)
		}
	}
	d = "every vault profile uses " + cliExePath()
	if len(bad) > 0 {
		d = "not wired (or pointing elsewhere): " + strings.Join(bad, ", ")
	}
	cs = append(cs, Check{"AWS CLI wired to the vault", len(bad) == 0, d, "zsp repair"})

	// Config guard.
	if resp, err := b.Do(&Request{Op: "guard-status", Snap: buildSnapshot()}); err == nil {
		var g map[string][]GuardFinding
		_ = json.Unmarshal(resp.Data, &g)
		if n := len(g["unapproved"]); n > 0 {
			var ks []string
			for _, f := range g["unapproved"] {
				ks = append(ks, f.Key)
			}
			cs = append(cs, Check{"No unapproved traffic redirection", false, strings.Join(ks, ", "), "remove them, or `zsp guard approve` if you made them"})
		} else {
			cs = append(cs, Check{"No unapproved traffic redirection", true, fmt.Sprintf("%d approved setting(s) present", len(g["found"])), ""})
		}
	}

	// Watcher.
	if sd.Settings.AutoMove {
		cmd, auto := autostartInstalled()
		run := watcherRunning()
		cs = append(cs, Check{"Automatic move (watcher)", auto && run, fmt.Sprintf("autostart=%v running=%v %s", auto, run, truncate(cmd, 60)), "zsp install"})
	} else {
		cs = append(cs, Check{"Automatic move (watcher)", true, "off by choice", ""})
	}

	// AWS CLI v2.
	if out, err := exec.Command("aws", "--version").CombinedOutput(); err != nil {
		cs = append(cs, Check{"AWS CLI v2", false, "aws not found on PATH", "install AWS CLI v2"})
	} else {
		ver := strings.TrimSpace(string(out))
		cs = append(cs, Check{"AWS CLI v2", strings.HasPrefix(ver, "aws-cli/2"), truncate(ver, 60), "AWS CLI v1 handles credential_process poorly; install v2"})
	}
	cs = append(cs, clockCheck())
	return cs
}

func clockCheck() Check {
	req, _ := http.NewRequest("HEAD", "https://sts.amazonaws.com/", nil)
	resp, err := httpClient.Do(req)
	if err != nil {
		return Check{"AWS reachable, clock in sync", false, "cannot reach sts.amazonaws.com: " + err.Error(), "check network / proxy"}
	}
	resp.Body.Close()
	t, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return Check{"AWS reachable, clock in sync", true, "reachable (no Date header)", ""}
	}
	skew := time.Since(t)
	if skew < 0 {
		skew = -skew
	}
	return Check{"AWS reachable, clock in sync", skew < 4*time.Minute,
		fmt.Sprintf("clock is %s off AWS (AWS refuses signed requests at 5 min)", skew.Round(time.Second)), "w32tm /resync"}
}

func printChecks(cs []Check) int {
	bad := 0
	for _, c := range cs {
		mark := "  OK "
		if !c.OK {
			mark = "  !! "
			bad++
		}
		fmt.Printf("%s %-42s %s\n", mark, c.Name, c.Detail)
		if !c.OK && c.Fix != "" {
			fmt.Printf("      %-42s fix: %s\n", "", c.Fix)
		}
	}
	return bad
}

// userModeLeftovers counts keys still sealed in the user-mode vault.
func userModeLeftovers() int {
	entries, _ := os.ReadDir(userVaultDir() + string(os.PathSeparator) + "keys")
	n := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sealed") {
			n++
		}
	}
	return n
}

func wiredToZsp(line string) bool {
	for _, exe := range append([]string{cliExePath()}, zspInstallPaths()...) {
		if credentialProcessOK(line, exe) {
			return true
		}
	}
	return false
}
