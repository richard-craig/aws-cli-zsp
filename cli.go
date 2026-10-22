// aws-cli-zsp for Windows: Zero Standing Permissions for the AWS keys on your PC.
//
// Long-lived AWS keys leave ~/.aws and are sealed by Windows Hello keys that
// live in the TPM. The AWS CLI and every SDK get only short STS sessions via
// credential_process. Two install modes:
//
//   - user mode (no admin): the vault and engine run as you;
//   - service mode (admin install): a Windows service holds the vault, the
//     session cache and the audit trail outside your account's reach.
//
// Windows port and extension of Andrew Baker's macOS aws-cli-zsp.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func usage() {
	fmt.Print(`aws-cli-zsp for Windows ` + version_ + ` — Zero Standing Permissions for AWS keys

Everyday
  zsp status                           mode, keys, live sessions, last use
  zsp test --profile P [--tier write]  real AWS call through the vault
  zsp approve --profile P [--tier write] CODE   session from your phone's 6-digit code
  zsp clear-sessions [--profile P]     drop cached sessions (next use asks again)

Install and set up
  zsp setup [--move a,b|all] [--keep c] [--auto on|off] [--duration 1h] [--yes]
  zsp install                          user mode: copy to %LOCALAPPDATA%, start the watcher
  zsp install --service [--service-account LocalSystem]     (elevated) service mode
  zsp uninstall [--restore-plaintext] [--purge]
  zsp uninstall --service [--purge]                          (elevated)
  zsp service status | migrate [--keep-local] | reset-user --sid S (elevated)
  zsp import | doctor | repair

Keys
  zsp check | rotate | revoke | adopt | restore [--force] --profile P
  zsp pin reset --profile P
  zsp config show | set NAME VALUE [--profile P]

MFA and phone
  zsp mfa enable --device pc|phone --profile P
  zsp mfa disable | enforce | unenforce --profile P
  zsp phone add | remove --profile P

Containment (v0.2/v0.3)
  zsp tier set --profile P [--read-role ARN] [--write-role ARN] [--write-duration 15m] [--write-profile N] [--no-verify]
  zsp tier clear | show --profile P
  zsp netbind --profile P --cidr 196.25.1.0/24[,...] [--force]  |  zsp netbind --profile P --off
  zsp guard status | approve
  zsp callers forget [--profile P]

Audit
  zsp audit show [-n 30] | verify | export
  zsp ship setup --bucket B --region R [--prefix P] | now | off

Called by the AWS CLI
  zsp credential-process --profile P [--tier write]

Settings for "zsp config set": duration, auto-move, keep, unkeep, idle-minutes,
reuse-idle-minutes, reuse-presence (lock+idle|lock|off), keep-sessions-on-lock,
new-caller-approval, sensitive-commands (comma list | default)
`)
}

func main() {
	// In service mode every profile must point at the installed copy in Program
	// Files: the service refuses any other zsp.exe as a client.
	if installed, _ := serviceState(); installed {
		if p := serviceExePath(); p != "" {
			cliExeOverride = p
		}
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "aws-cli-zsp:", err)
		os.Exit(1)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func profileDefault() string {
	if p := os.Getenv("AWS_PROFILE"); p != "" {
		return p
	}
	return "default"
}

// flags is a tiny wrapper so every command parses the same way and accepts
// flags before or after positional arguments.
type flags struct {
	fs   *flag.FlagSet
	args []string
}

func newFlags(name string) *flags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return &flags{fs: fs}
}

func (f *flags) parse(args []string) error {
	var pos []string
	for len(args) > 0 {
		if err := f.fs.Parse(args); err != nil {
			return err
		}
		args = f.fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	f.args = pos
	return nil
}

func (f *flags) arg(i int) string {
	if i < len(f.args) {
		return f.args[i]
	}
	return ""
}

func run(cmd string, args []string) error {
	ui := consoleUI{out: os.Stdout}
	backend := func() (Backend, error) { return openBackend(ui, false) }

	switch cmd {
	case "help", "-h", "--help":
		usage()
		return nil
	case "version", "--version":
		fmt.Println("aws-cli-zsp-windows", version_)
		return nil

	case "credential-process":
		f := newFlags(cmd)
		p := f.fs.String("profile", profileDefault(), "")
		tier := f.fs.String("tier", "", "")
		if err := f.parse(args); err != nil {
			return err
		}
		b, err := openBackend(consoleUI{out: os.Stderr}, false)
		if err != nil {
			return err
		}
		resp, err := b.Do(&Request{Op: "credential", Profile: *p, Tier: *tier, Snap: buildSnapshot()})
		if err != nil {
			return err
		}
		if resp.Session == nil {
			return errors.New("no session returned")
		}
		os.Stdout.Write(credentialProcessJSON(resp.Session))
		return nil

	case "approve":
		f := newFlags(cmd)
		p := f.fs.String("profile", profileDefault(), "")
		tier := f.fs.String("tier", "", "")
		if err := f.parse(args); err != nil {
			return err
		}
		if len(f.args) != 1 {
			return errors.New("usage: zsp approve --profile P [--tier write] 123456")
		}
		b, err := backend()
		if err != nil {
			return err
		}
		resp, err := b.Do(&Request{Op: "approve", Profile: *p, Tier: *tier, Args: map[string]string{"code": f.arg(0)}, Snap: buildSnapshot()})
		if err != nil {
			return err
		}
		fmt.Printf("approved: %s (%s) has a session until %s\n", *p, resp.Session.Tier, resp.Session.Expiration.Local().Format("15:04"))
		return nil

	case "setup":
		return cmdSetup(args)
	case "install":
		f := newFlags(cmd)
		svc := f.fs.Bool("service", false, "")
		acct := f.fs.String("service-account", "", "")
		if err := f.parse(args); err != nil {
			return err
		}
		if *svc {
			return cmdServiceInstall(*acct)
		}
		return cmdInstallUser()
	case "uninstall":
		f := newFlags(cmd)
		svc := f.fs.Bool("service", false, "")
		restore := f.fs.Bool("restore-plaintext", false, "")
		purge := f.fs.Bool("purge", false, "")
		if err := f.parse(args); err != nil {
			return err
		}
		if *svc {
			return cmdServiceUninstall(*purge)
		}
		return cmdUninstallUser(*restore, *purge)
	case "service":
		return cmdService(args)
	case "service-run":
		return cmdServiceRun()

	case "import":
		b, err := backend()
		if err != nil {
			return err
		}
		sd, err := statusOf(b)
		if err != nil {
			return err
		}
		res, err := importKeys(b, nil, sd.Settings, "zsp import")
		printImport(res)
		return err

	case "watch":
		return cmdWatch()

	case "status", "list":
		b, err := backend()
		if err != nil {
			return err
		}
		return cmdStatus(b)

	case "doctor":
		b, err := backend()
		if err != nil {
			return err
		}
		sd, err := statusOf(b)
		if err != nil {
			return err
		}
		cs := append(clientChecks(b, sd), sd.Checks...)
		if bad := printChecks(cs); bad > 0 {
			return fmt.Errorf("%d check(s) need attention", bad)
		}
		return nil

	case "repair":
		b, err := backend()
		if err != nil {
			return err
		}
		sd, err := statusOf(b)
		if err != nil {
			return err
		}
		fixed, err := repairWiring(sd)
		if err != nil {
			return err
		}
		fmt.Printf("Rewired %d profile(s) to %s %s\n", len(fixed), cliExePath(), strings.Join(fixed, ", "))
		if b.Mode() == ModeUser && sd.Settings.AutoMove {
			return cmdInstallUser()
		}
		return nil

	case "clear-sessions":
		f := newFlags(cmd)
		p := f.fs.String("profile", "", "")
		if err := f.parse(args); err != nil {
			return err
		}
		b, err := backend()
		if err != nil {
			return err
		}
		resp, err := b.Do(&Request{Op: "clear-sessions", Profile: *p})
		if err != nil {
			return err
		}
		fmt.Printf("cleared %s session(s)\n", resp.Text)
		return nil

	case "test", "check", "rotate", "revoke", "adopt", "restore":
		f := newFlags(cmd)
		p := f.fs.String("profile", profileDefault(), "")
		tier := f.fs.String("tier", "", "")
		force := f.fs.Bool("force", false, "")
		if err := f.parse(args); err != nil {
			return err
		}
		b, err := backend()
		if err != nil {
			return err
		}
		req := &Request{Op: cmd, Profile: *p, Tier: *tier, Snap: buildSnapshot(), Args: map[string]string{}}
		if *force {
			req.Args["force"] = "1"
		}
		resp, err := b.Do(req)
		if err != nil {
			return err
		}
		if cmd == "restore" && resp.Key != nil {
			if err := writePlaintextKey(*p, resp.Key.AccessKeyID, resp.Key.SecretAccessKey); err != nil {
				return fmt.Errorf("the key left the vault but writing ~/.aws/credentials failed: %w", err)
			}
			_ = unwireProfile(*p)
			fmt.Printf("%s is back in ~/.aws/credentials as plain text (and on the keep list).\n", *p)
		}
		return nil

	case "pin":
		if len(args) == 0 || args[0] != "reset" {
			return errors.New("usage: zsp pin reset --profile P")
		}
		return simpleOp("pin-reset", args[1:], nil)

	case "mfa":
		if len(args) == 0 {
			return errors.New("usage: zsp mfa enable|disable|enforce|unenforce --profile P")
		}
		switch args[0] {
		case "enable":
			f := newFlags(cmd)
			p := f.fs.String("profile", profileDefault(), "")
			dev := f.fs.String("device", "pc", "")
			if err := f.parse(args[1:]); err != nil {
				return err
			}
			return doOp(&Request{Op: "mfa-enable", Profile: *p, Args: map[string]string{"device": *dev}, Snap: buildSnapshot()})
		case "disable", "enforce", "unenforce":
			return simpleOp("mfa-"+args[0], args[1:], nil)
		}
		return fmt.Errorf("unknown: zsp mfa %s", args[0])

	case "phone":
		if len(args) == 0 || (args[0] != "add" && args[0] != "remove") {
			return errors.New("usage: zsp phone add|remove --profile P")
		}
		return simpleOp("phone-"+args[0], args[1:], nil)

	case "netbind":
		f := newFlags(cmd)
		p := f.fs.String("profile", profileDefault(), "")
		cidr := f.fs.String("cidr", "", "")
		off := f.fs.Bool("off", false, "")
		force := f.fs.Bool("force", false, "")
		if err := f.parse(args); err != nil {
			return err
		}
		c := *cidr
		if *off {
			c = "off"
		}
		if c == "" {
			return errors.New("usage: zsp netbind --profile P --cidr 196.25.1.0/24[,...]  |  --off")
		}
		a := map[string]string{"cidrs": c}
		if *force {
			a["force"] = "1"
		}
		return doOp(&Request{Op: "netbind", Profile: *p, Args: a, Snap: buildSnapshot()})

	case "tier":
		return cmdTier(args)

	case "guard":
		action := "status"
		if len(args) > 0 {
			action = args[0]
		}
		b, err := backend()
		if err != nil {
			return err
		}
		switch action {
		case "approve":
			_, err := b.Do(&Request{Op: "guard-approve", Snap: buildSnapshot()})
			return err
		case "status":
			resp, err := b.Do(&Request{Op: "guard-status", Snap: buildSnapshot()})
			if err != nil {
				return err
			}
			var g map[string][]GuardFinding
			_ = json.Unmarshal(resp.Data, &g)
			bad := map[string]bool{}
			for _, x := range g["unapproved"] {
				bad[x.Key] = true
			}
			if len(g["found"]) == 0 {
				fmt.Println("No settings redirect or intercept AWS traffic.")
			}
			for _, x := range g["found"] {
				mark := "approved  "
				if bad[x.Key] {
					mark = "UNAPPROVED"
				}
				fmt.Printf("  %s  %s = %s\n", mark, x.Key, truncate(x.Value, 100))
			}
			if len(bad) > 0 {
				return fmt.Errorf("%d unapproved setting(s): credentials are refused until you remove them or run `zsp guard approve`", len(bad))
			}
			return nil
		}
		return fmt.Errorf("unknown: zsp guard %s", action)

	case "callers":
		if len(args) == 0 || args[0] != "forget" {
			return errors.New("usage: zsp callers forget [--profile P]")
		}
		f := newFlags(cmd)
		p := f.fs.String("profile", "", "")
		if err := f.parse(args[1:]); err != nil {
			return err
		}
		return doOp(&Request{Op: "callers-forget", Profile: *p})

	case "config":
		return cmdConfig(args)
	case "audit":
		return cmdAudit(args)
	case "ship":
		return cmdShip(args)
	}
	usage()
	return fmt.Errorf("unknown command %q", cmd)
}

func doOp(req *Request) error {
	b, err := openBackend(consoleUI{out: os.Stdout}, false)
	if err != nil {
		return err
	}
	_, err = b.Do(req)
	return err
}

func simpleOp(op string, args []string, extra map[string]string) error {
	f := newFlags(op)
	p := f.fs.String("profile", profileDefault(), "")
	if err := f.parse(args); err != nil {
		return err
	}
	return doOp(&Request{Op: op, Profile: *p, Args: extra, Snap: buildSnapshot()})
}

// setup ------------------------------------------------------------------------------------

func askYes(in *bufio.Reader, q string, def bool) bool {
	fmt.Print(q)
	ans, _ := in.ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(ans))
	if a == "" {
		return def
	}
	return a == "y" || a == "yes"
}

func cmdSetup(args []string) error {
	f := newFlags("setup")
	move := f.fs.String("move", "", "")
	keep := f.fs.String("keep", "", "")
	auto := f.fs.String("auto", "", "")
	dur := f.fs.String("duration", "", "")
	yes := f.fs.Bool("yes", false, "")
	if err := f.parse(args); err != nil {
		return err
	}
	ui := consoleUI{out: os.Stdout}
	in := bufio.NewReader(os.Stdin)
	installed, _ := serviceState()

	if installed {
		fmt.Println("Service mode: registering your Windows Hello key with the zsp service (you may be asked to approve)...")
		pub, err := localHelloPublicKey(true)
		if err != nil {
			return err
		}
		b, err := openBackend(ui, false)
		if err != nil {
			return err
		}
		if _, err := b.Do(&Request{Op: "enroll", Args: map[string]string{"pub": encodePublicKey(pub)}}); err != nil {
			return err
		}
		if n := userModeLeftovers(); n > 0 {
			fmt.Printf("\nYou have %d key(s) in a user-mode vault from before the service was installed.\nMove them into the service with:  zsp service migrate\n\n", n)
		}
	} else {
		fmt.Println("User mode: creating your Windows Hello keys (you may be asked to approve twice)...")
	}
	b, err := openBackend(ui, true)
	if err != nil {
		return err
	}
	sd, err := statusOf(b)
	if err != nil {
		return err
	}
	set := func(name, value string) error {
		_, err := b.Do(&Request{Op: "setting", Args: map[string]string{"name": name, "value": value}})
		return err
	}
	if *dur != "" {
		if err := set("duration", *dur); err != nil {
			return err
		}
	}
	found, err := findPlaintextKeys()
	if err != nil {
		return err
	}
	selected := map[string]bool{}
	var keepList []string
	keepList = append(keepList, splitList(*keep)...)
	isKeep := func(p string) bool {
		for _, k := range keepList {
			if strings.EqualFold(k, p) {
				return true
			}
		}
		return false
	}
	autoVal := strings.ToLower(*auto)
	switch {
	case *move == "all":
		for _, k := range found {
			if !isKeep(k.Profile) {
				selected[k.Profile] = true
			}
		}
	case *move != "":
		for _, k := range splitList(*move) {
			selected[k] = true
		}
	case len(found) > 0 && !*yes:
		fmt.Println("\nPlaintext keys found:")
		for _, k := range found {
			if askYes(in, fmt.Sprintf("  Move '%s' (%s, ~/.aws/%s) into the vault? [Y/n] ", k.Profile, maskKeyID(k.AKID), k.File), true) {
				selected[k.Profile] = true
			} else {
				keepList = append(keepList, k.Profile)
			}
		}
		if autoVal == "" {
			if askYes(in, "Move keys written to ~/.aws later automatically? [Y/n] ", true) {
				autoVal = "on"
			} else {
				autoVal = "off"
			}
		}
	}
	if len(keepList) > 0 {
		if err := set("keep", strings.Join(keepList, ",")); err != nil {
			return err
		}
	}
	var unkeep []string
	for p := range selected {
		if sd.Settings.isKept(p) {
			unkeep = append(unkeep, p)
		}
	}
	if len(unkeep) > 0 {
		if err := set("unkeep", strings.Join(unkeep, ",")); err != nil {
			return err
		}
	}
	if autoVal == "on" || autoVal == "off" {
		if err := set("auto-move", autoVal); err != nil {
			return err
		}
	}
	if len(selected) > 0 {
		res, err := importKeys(b, selected, sd.Settings, "zsp setup")
		printImport(res)
		if err != nil {
			return err
		}
	} else {
		fmt.Println("No keys moved.")
	}

	// Config guard: show what redirects AWS traffic today and approve it once.
	if resp, err := b.Do(&Request{Op: "guard-status", Snap: buildSnapshot()}); err == nil {
		var g map[string][]GuardFinding
		_ = json.Unmarshal(resp.Data, &g)
		if len(g["unapproved"]) > 0 {
			fmt.Println("\nThese settings redirect or intercept AWS traffic (proxy, CA bundle, custom endpoints):")
			for _, x := range g["unapproved"] {
				fmt.Printf("  %s = %s\n", x.Key, truncate(x.Value, 100))
			}
			if *yes || askYes(in, "Approve them now? zsp refuses credentials while unapproved ones exist. [Y/n] ", true) {
				if _, err := b.Do(&Request{Op: "guard-approve", Snap: buildSnapshot()}); err != nil {
					return err
				}
			}
		}
	}

	if b.Mode() == ModeUser {
		if err := cmdInstallUser(); err != nil {
			fmt.Fprintln(os.Stderr, "install step failed:", err)
		}
	} else if !watcherRunning() {
		_ = startWatcher(filepath.Join(filepath.Dir(cliExePath()), "zspw.exe"))
	}
	sd, _ = statusOf(b)
	fmt.Printf("\nDone (%s mode). Sessions last %s. Try:  aws sts get-caller-identity --profile <name>\nThen:     zsp doctor\n", b.Mode(), sd.Settings.DefaultDuration)
	return nil
}

func printImport(r importResult) {
	for _, p := range r.Moved {
		fmt.Printf("  sealed   %s  (removed from ~/.aws, credential_process wired)\n", p)
	}
	for _, p := range r.Quarantined {
		fmt.Printf("  QUARANTINED %s: a new key was written over an MFA-protected profile. Run: zsp adopt --profile %s\n", p, p)
	}
	for _, p := range r.Skipped {
		fmt.Printf("  skipped  %s\n", p)
	}
}

// user-mode install ----------------------------------------------------------------------------

func userInstallDir() string {
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return filepath.Join(d, "Programs", "aws-cli-zsp")
	}
	return filepath.Dir(cliExePath())
}

func copyFile(src, dst string) error {
	if strings.EqualFold(filepath.Clean(src), filepath.Clean(dst)) {
		return nil
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, b, 0o755)
}

func cmdInstallUser() error {
	if installed, _ := serviceState(); installed {
		return errors.New("the zsp service is installed; user-mode install is not needed (see `zsp service status`)")
	}
	exe, _ := os.Executable()
	src := filepath.Dir(exe)
	dst := userInstallDir()
	for _, n := range []string{"zsp.exe", "zspw.exe"} {
		if err := copyFile(filepath.Join(src, n), filepath.Join(dst, n)); err != nil {
			return fmt.Errorf("copy %s (keep zsp.exe and zspw.exe in the same folder): %w", n, err)
		}
	}
	e, err := openUserEngine(false)
	if err != nil {
		return err
	}
	auto := e.settings().AutoMove
	watcher := filepath.Join(dst, "zspw.exe")
	if auto {
		if err := installAutostart(watcher, false); err != nil {
			return err
		}
		if !watcherRunning() {
			if err := startWatcher(watcher); err != nil {
				return err
			}
		}
	} else {
		stopWatcher()
		_ = removeAutostart(false)
	}
	// Point profiles at the installed copy.
	cliExeOverride = filepath.Join(dst, "zsp.exe")
	defer func() { cliExeOverride = "" }()
	sd := &StatusData{Settings: e.settings()}
	for _, p := range e.profiles() {
		sd.Profiles = append(sd.Profiles, ProfileStatus{Name: p, Policy: sd.Settings.policy(p)})
	}
	if _, err := repairWiring(sd); err != nil {
		return err
	}
	if auto {
		fmt.Printf("Installed to %s; the watcher starts at sign-in and is running now.\n", dst)
	} else {
		fmt.Printf("Installed to %s (automatic move is off, so no watcher).\n", dst)
	}
	fmt.Printf("Optional, to type `zsp` anywhere (PowerShell):\n  [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';%s', 'User')\n", dst)
	return nil
}

func cmdUninstallUser(restore, purge bool) error {
	if installed, _ := serviceState(); installed {
		return errors.New("service mode is installed: use `zsp uninstall --service` from an elevated terminal (restore keys first with `zsp restore`)")
	}
	stopWatcher()
	_ = removeAutostart(false)
	e, err := openUserEngine(false)
	if err != nil && (restore || purge) {
		return err
	}
	if restore && e != nil {
		b := &localBackend{e: e, ui: consoleUI{out: os.Stdout}}
		for _, p := range e.profiles() {
			resp, err := b.Do(&Request{Op: "restore", Profile: p})
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			if err := writePlaintextKey(p, resp.Key.AccessKeyID, resp.Key.SecretAccessKey); err != nil {
				return err
			}
			_ = unwireProfile(p)
			fmt.Println("restored", p)
		}
	}
	if purge {
		if e != nil {
			if left := e.profiles(); len(left) > 0 {
				return fmt.Errorf("refusing to purge: still sealed: %s (use --restore-plaintext)", strings.Join(left, ", "))
			}
		}
		if err := deleteHardwareKeys(); err != nil {
			return err
		}
		if err := os.RemoveAll(userVaultDir()); err != nil {
			return err
		}
	}
	fmt.Println("Watcher stopped and autostart removed.")
	return nil
}

// service subcommands that are not install/uninstall ----------------------------------------------

func cmdService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: zsp service status | migrate [--keep-local] | reset-user --sid S")
	}
	switch args[0] {
	case "status":
		installed, running := serviceState()
		fmt.Printf("installed: %v   running: %v\n", installed, running)
		if !installed || !running {
			return nil
		}
		b, err := openBackend(consoleUI{out: os.Stdout}, false)
		if err != nil {
			return err
		}
		resp, err := b.Do(&Request{Op: "ping"})
		if err != nil {
			return err
		}
		sd, err := statusOf(b)
		if err != nil {
			return err
		}
		fmt.Printf("service: %s   key backend: %s   you are enrolled: %v   keys: %d\n", resp.Text, sd.Backend, sd.Enrolled, len(sd.Profiles))
		return nil
	case "migrate":
		f := newFlags("migrate")
		keepLocal := f.fs.Bool("keep-local", false, "")
		if err := f.parse(args[1:]); err != nil {
			return err
		}
		return cmdMigrate(*keepLocal)
	case "reset-user":
		f := newFlags("reset-user")
		sid := f.fs.String("sid", "", "")
		if err := f.parse(args[1:]); err != nil {
			return err
		}
		return cmdServiceResetUser(*sid)
	}
	return fmt.Errorf("unknown: zsp service %s", args[0])
}

// cmdMigrate moves every key from the user-mode vault into the service: one
// Windows Hello approval per key, then the user-mode copies are deleted.
func cmdMigrate(keepLocal bool) error {
	installed, running := serviceState()
	if !installed || !running {
		return errors.New("the zsp service is not installed and running")
	}
	ui := consoleUI{out: os.Stdout}
	local, err := openUserEngine(false)
	if err != nil {
		return fmt.Errorf("no user-mode vault to migrate: %w", err)
	}
	local.UI = ui
	local.Caller = CallerInfo{Desc: "zsp service migrate"}
	pub, err := localHelloPublicKey(true)
	if err != nil {
		return err
	}
	svc := &serviceBackend{ui: ui}
	if _, err := svc.Do(&Request{Op: "enroll", Args: map[string]string{"pub": encodePublicKey(pub)}}); err != nil {
		return err
	}
	st := local.settings()
	moved := map[string]bool{}
	already := map[string]bool{}
	if sd, err := statusOf(svc); err == nil {
		for _, p := range sd.Profiles {
			already[p.Name] = true
		}
	}
	for _, p := range local.profiles() {
		if already[p] {
			fmt.Printf("  %s is already in the service (left as is)\n", p)
			moved[p] = true
			continue
		}
		k, env, err := local.OpenKey(p, fmt.Sprintf("Move AWS key '%s' from your user-mode vault into the zsp service.", p))
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		bundle := &MigrationBundle{Key: k, Meta: env.Meta}
		if pc, err := local.loadPhoneCopy(p); err == nil {
			bundle.Phone = pc
		}
		if pin, err := local.LoadPin(p); err == nil && pin != nil {
			bundle.Pin = pin
		}
		if pol := st.policy(p); pol != (ProfilePolicy{}) {
			bundle.Pol = &pol
		}
		_, err = svc.Do(&Request{Op: "migrate", Profile: p, Bundle: bundle})
		k.wipe()
		if bundle.Phone != nil {
			bundle.Phone.SecretAccessKey = ""
		}
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		moved[p] = true
		fmt.Printf("  moved %s\n", p)
	}
	// Carry the user's preferences across (each one is Hello-gated in the service).
	if len(st.Keep) > 0 {
		_, _ = svc.Do(&Request{Op: "setting", Args: map[string]string{"name": "keep", "value": strings.Join(st.Keep, ",")}})
	}
	if !st.AutoMove {
		_, _ = svc.Do(&Request{Op: "setting", Args: map[string]string{"name": "auto-move", "value": "off"}})
	}
	sd, err := statusOf(svc)
	if err != nil {
		return err
	}
	if fixed, err := repairWiring(sd); err != nil {
		return err
	} else if len(fixed) > 0 {
		fmt.Printf("  rewired %s to %s\n", strings.Join(fixed, ", "), cliExePath())
	}
	// Retire user mode: stop the per-user watcher; the service install runs one for every user.
	_ = removeAutostart(false)
	if !keepLocal {
		for p := range moved {
			for _, f := range []string{local.keyPath(p), local.phonePath(p), local.pinPath(p), local.incomingPath(p)} {
				os.Remove(f)
			}
		}
		local.clearSessions("")
		fmt.Println("  user-mode copies deleted")
	}
	fmt.Printf("Migrated %d key(s) into the service. Check with: zsp doctor\n", len(moved))
	return nil
}

// watcher ---------------------------------------------------------------------------------------

type nullUI struct{}

func (nullUI) Printf(string, ...any)      {}
func (nullUI) Ask(string) (string, error) { return "", errors.New("the watcher cannot ask questions") }
func (nullUI) HelloUnwrap([]byte, string) ([]byte, error) {
	return nil, errors.New("the watcher cannot ask for Windows Hello")
}

func cmdWatch() error {
	release, ok := singleInstance("aws-cli-zsp-watcher")
	if !ok {
		return nil // already running in this session
	}
	defer release()
	_ = os.MkdirAll(awsDir(), 0o700)
	var b Backend
	var err error
	for i := 0; ; i++ { // the service may still be starting at sign-in
		if b, err = openBackend(nullUI{}, false); err == nil {
			break
		}
		if i > 60 {
			return err
		}
		time.Sleep(5 * time.Second)
	}
	wasLocked := false
	lastSweep := time.Time{}
	for {
		// User mode clears sessions on lock itself; the service does it from WTS events.
		if b.Mode() == ModeUser {
			locked := localLocked()
			if locked && !wasLocked {
				_, _ = b.Do(&Request{Op: "lock-clear"})
			}
			wasLocked = locked
		}
		changed := waitForChange(awsDir(), 3*time.Second)
		if !changed && time.Since(lastSweep) < 5*time.Minute {
			continue
		}
		if changed {
			time.Sleep(1500 * time.Millisecond) // let `aws configure` finish writing both files
		}
		lastSweep = time.Now()
		sd, err := statusOf(b)
		if err != nil || !sd.Enrolled {
			continue
		}
		if sd.Settings.AutoMove {
			if res, err := importKeys(b, nil, sd.Settings, "watcher"); err == nil {
				if n := len(res.Moved) + len(res.Quarantined); n > 0 {
					notify(fmt.Sprintf("Moved %d AWS key(s) into the vault: %s", n, strings.Join(append(res.Moved, res.Quarantined...), ", ")))
					sd, _ = statusOf(b)
				}
			}
		}
		if sd != nil {
			if fixed, err := repairWiring(sd); err == nil && len(fixed) > 0 {
				notify("credential_process was changed for " + strings.Join(fixed, ", ") + "; zsp put it back. If you did not do this, run zsp doctor.")
			}
		}
		if b.Mode() == ModeUser && sd != nil && sd.Settings.Ship != nil {
			_, _ = b.Do(&Request{Op: "ship-now"})
		}
	}
}

// status ------------------------------------------------------------------------------------------

func cmdStatus(b Backend) error {
	sd, err := statusOf(b)
	if err != nil {
		return err
	}
	found, _ := findPlaintextKeys()
	state := "PROTECTED"
	for _, k := range found {
		if !sd.Settings.isKept(k.Profile) {
			state = "AT RISK: plaintext key in ~/.aws (" + k.Profile + ")"
		}
	}
	if !sd.Enrolled {
		state = "NOT SET UP (run zsp setup)"
	}
	fmt.Printf("%s · %s mode · %d key(s) · auto-move %v · default session %s · reuse needs %s\n\n",
		state, sd.Mode, len(sd.Profiles), sd.Settings.AutoMove, sd.Settings.DefaultDuration, sd.Settings.ReusePresence)
	for _, p := range sd.Profiles {
		sess := "no session"
		var parts []string
		for _, s := range p.Sessions {
			parts = append(parts, fmt.Sprintf("%s until %s (%s)", s.Tier, s.Expires.Local().Format("15:04"), s.Source))
		}
		if len(parts) > 0 {
			sess = strings.Join(parts, ", ")
		}
		var flags []string
		switch p.Meta["mfa"] {
		case "pc":
			flags = append(flags, "MFA on this PC")
		case "phone":
			flags = append(flags, "MFA on phone")
		}
		if p.Meta["enforced"] == "yes" {
			flags = append(flags, "AWS requires MFA")
		}
		if p.Phone {
			flags = append(flags, "phone approval")
		}
		if p.Meta["netbind"] == "yes" {
			flags = append(flags, "source-IP bound")
		}
		if p.Policy.ReadRole != "" || p.Policy.WriteRole != "" {
			flags = append(flags, "tiers (write: "+orDash(p.Policy.WriteProfile)+")")
		}
		if p.Meta["readonly"] == "yes" {
			flags = append(flags, "read-only · client's key")
		}
		if p.Incoming {
			flags = append(flags, "QUARANTINED NEW KEY")
		}
		fmt.Printf("  %-18s %-22s %s\n", p.Name, p.Meta["akid_masked"], sess)
		if len(flags) > 0 {
			fmt.Printf("  %-18s %s\n", "", strings.Join(flags, " · "))
		}
		if !p.LastUsed.IsZero() {
			fmt.Printf("  %-18s last used %s by %s\n", "", p.LastUsed.Local().Format("Jan 02 15:04"), truncate(p.LastCaller, 60))
		}
	}
	if len(sd.Settings.Keep) > 0 {
		fmt.Printf("\n  left in plain text by choice: %s\n", strings.Join(sd.Settings.Keep, ", "))
	}
	if sd.Settings.Ship != nil && sd.Ship != nil {
		fmt.Printf("  audit shipped to s3://%s/%s (%d entries, last %s)\n", sd.Settings.Ship.Bucket, sd.Settings.Ship.Prefix, sd.Ship.Index, sd.Ship.LastShip.Local().Format("Jan 02 15:04"))
	}
	return nil
}

// tier --------------------------------------------------------------------------------------------

func cmdTier(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: zsp tier set|clear|show --profile P ...")
	}
	f := newFlags("tier")
	p := f.fs.String("profile", profileDefault(), "")
	read := f.fs.String("read-role", "", "")
	write := f.fs.String("write-role", "", "")
	wdur := f.fs.String("write-duration", "", "")
	wprof := f.fs.String("write-profile", "", "")
	noVerify := f.fs.Bool("no-verify", false, "")
	if err := f.parse(args[1:]); err != nil {
		return err
	}
	b, err := openBackend(consoleUI{out: os.Stdout}, false)
	if err != nil {
		return err
	}
	switch args[0] {
	case "set":
		verify := "1"
		if *noVerify {
			verify = "0"
		}
		resp, err := b.Do(&Request{Op: "tier-set", Profile: *p, Snap: buildSnapshot(), Args: map[string]string{
			"read": *read, "write": *write, "write-duration": *wdur, "write-profile": *wprof, "verify": verify}})
		if err != nil {
			return err
		}
		var pol ProfilePolicy
		_ = json.Unmarshal(resp.Data, &pol)
		if pol.WriteProfile != "" && pol.WriteRole != "" {
			if err := wireWriteProfile(*p, pol.WriteProfile); err != nil {
				return err
			}
		}
		fmt.Printf("Tiers for %s:\n  read  (profile %s): %s\n  write (profile %s): %s\n", *p, *p, orDash(pol.ReadRole), orDash(pol.WriteProfile), orDash(pol.WriteRole))
		if pol.WriteRole != "" {
			fmt.Printf("Use `aws --profile %s ...` for changes; each new write session asks Windows Hello.\n", pol.WriteProfile)
		}
		return nil
	case "clear":
		resp, err := b.Do(&Request{Op: "tier-clear", Profile: *p})
		if err != nil {
			return err
		}
		var old ProfilePolicy
		_ = json.Unmarshal(resp.Data, &old)
		if old.WriteProfile != "" {
			_ = removeProfileSection(old.WriteProfile)
		}
		fmt.Println("tiers removed for", *p)
		return nil
	case "show":
		sd, err := statusOf(b)
		if err != nil {
			return err
		}
		for _, ps := range sd.Profiles {
			if ps.Name == *p {
				fmt.Printf("%s\n  read role:  %s\n  write role: %s\n  write profile: %s\n  write session: %s\n", ps.Name,
					orDash(ps.Policy.ReadRole), orDash(ps.Policy.WriteRole), orDash(ps.Policy.WriteProfile), sd.Settings.durationFor(ps.Name, tierWrite))
				return nil
			}
		}
		return fmt.Errorf("%s is not in the vault", *p)
	}
	return fmt.Errorf("unknown: zsp tier %s", args[0])
}

// config ------------------------------------------------------------------------------------------

func cmdConfig(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: zsp config show | set NAME VALUE [--profile P]")
	}
	f := newFlags("config")
	p := f.fs.String("profile", "", "")
	if err := f.parse(args[1:]); err != nil {
		return err
	}
	b, err := openBackend(consoleUI{out: os.Stdout}, false)
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		sd, err := statusOf(b)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(sd.Settings, "", "  ")
		fmt.Println(string(out))
		return nil
	case "set":
		if len(f.args) != 2 {
			return errors.New("usage: zsp config set NAME VALUE [--profile P]")
		}
		_, err := b.Do(&Request{Op: "setting", Profile: *p, Args: map[string]string{"name": f.arg(0), "value": f.arg(1)}})
		if err == nil {
			fmt.Printf("%s = %s\n", f.arg(0), f.arg(1))
		}
		return err
	}
	return fmt.Errorf("unknown: zsp config %s", args[0])
}

// audit -------------------------------------------------------------------------------------------

func cmdAudit(args []string) error {
	action := "show"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action, args = args[0], args[1:]
	}
	f := newFlags("audit")
	n := f.fs.Int("n", 30, "")
	if err := f.parse(args); err != nil {
		return err
	}
	b, err := openBackend(consoleUI{out: os.Stdout}, false)
	if err != nil {
		return err
	}
	fetch := func(n int) ([]AuditEntry, error) {
		resp, err := b.Do(&Request{Op: "audit-show", Args: map[string]string{"n": strconv.Itoa(n)}})
		if err != nil {
			return nil, err
		}
		var es []AuditEntry
		return es, json.Unmarshal(resp.Data, &es)
	}
	switch action {
	case "show":
		es, err := fetch(*n)
		if err != nil {
			return err
		}
		for _, a := range es {
			mark := "  "
			if !a.OK {
				mark = "!!"
			}
			fmt.Printf("%s %s %-19s %-12s %s", mark, a.TS.Local().Format("01-02 15:04:05"), a.Event, a.Profile, a.Detail)
			if a.Caller != "" {
				fmt.Printf("  ← %s", a.Caller)
			}
			fmt.Println()
		}
		return nil
	case "verify":
		resp, err := b.Do(&Request{Op: "audit-verify"})
		if err != nil {
			return err
		}
		fmt.Printf("audit chain intact (%s entries)\n", resp.Text)
		return nil
	case "export":
		sd, err := statusOf(b)
		if err != nil {
			return err
		}
		es, err := fetch(1 << 30)
		if err != nil {
			return err
		}
		name := fmt.Sprintf("aws-cli-zsp-report-%s.txt", time.Now().Format("20060102-150405"))
		var sb strings.Builder
		fmt.Fprintf(&sb, "aws-cli-zsp-windows %s report, %s, %s mode\n\n== health ==\n", version_, time.Now().Format(time.RFC3339), sd.Mode)
		for _, c := range append(clientChecks(b, sd), sd.Checks...) {
			fmt.Fprintf(&sb, "%v\t%s\t%s\n", c.OK, c.Name, redact(c.Detail))
		}
		sb.WriteString("\n== wiring ==\n")
		wired := wiredProfiles()
		keys := make([]string, 0, len(wired))
		for p := range wired {
			keys = append(keys, p)
		}
		sort.Strings(keys)
		for _, p := range keys {
			fmt.Fprintf(&sb, "%s: %s\n", p, wired[p])
		}
		sb.WriteString("\n== settings ==\n")
		js, _ := json.MarshalIndent(sd.Settings, "", "  ")
		sb.WriteString(redact(string(js)) + "\n\n== audit ==\n")
		for _, a := range es {
			fmt.Fprintf(&sb, "%s %v %s %s %s ← %s\n", a.TS.Format(time.RFC3339), a.OK, a.Event, a.Profile, redact(a.Detail), a.Caller)
		}
		if err := os.WriteFile(name, []byte(sb.String()), 0o600); err != nil {
			return err
		}
		fmt.Println("wrote", name, "(secrets never enter the audit; key ids masked, account ids cut to last 4)")
		return nil
	}
	return fmt.Errorf("usage: zsp audit show|verify|export")
}

// ship --------------------------------------------------------------------------------------------

func cmdShip(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: zsp ship setup --bucket B --region R [--prefix P] | now | off")
	}
	f := newFlags("ship")
	bucket := f.fs.String("bucket", "", "")
	region := f.fs.String("region", "", "")
	prefix := f.fs.String("prefix", "aws-cli-zsp", "")
	if err := f.parse(args[1:]); err != nil {
		return err
	}
	b, err := openBackend(consoleUI{out: os.Stdout}, false)
	if err != nil {
		return err
	}
	switch args[0] {
	case "setup":
		akid, err := consoleAsk("Shipping user's access key id: ")
		if err != nil {
			return err
		}
		secret, err := consoleAskSecret("Shipping user's secret access key (not echoed): ")
		if err != nil {
			return err
		}
		_, err = b.Do(&Request{Op: "ship-setup", Args: map[string]string{"bucket": *bucket, "region": *region, "prefix": *prefix,
			"akid": strings.TrimSpace(akid), "secret": strings.TrimSpace(secret)}})
		return err
	case "now":
		_, err := b.Do(&Request{Op: "ship-now"})
		if err == nil {
			fmt.Println("shipped")
		}
		return err
	case "off":
		_, err := b.Do(&Request{Op: "ship-off"})
		return err
	}
	return fmt.Errorf("unknown: zsp ship %s", args[0])
}
