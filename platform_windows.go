//go:build windows

package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	serviceName = "AwsCliZsp"
	pipeName    = `\\.\pipe\aws-cli-zsp`
	eventSource = "aws-cli-zsp"
	runKeyPath  = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue    = "aws-cli-zsp watcher"
)

var (
	modUser32   = windows.NewLazySystemDLL("user32.dll")
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procGetConsoleWindow           = modKernel32.NewProc("GetConsoleWindow")
	procGetForegroundWindow        = modUser32.NewProc("GetForegroundWindow")
	procIsWindowVisible            = modUser32.NewProc("IsWindowVisible")
	procOpenInputDesktop           = modUser32.NewProc("OpenInputDesktop")
	procSwitchDesktop              = modUser32.NewProc("SwitchDesktop")
	procCloseDesktop               = modUser32.NewProc("CloseDesktop")
	procGetLastInputInfo           = modUser32.NewProc("GetLastInputInfo")
	procGetTickCount               = modKernel32.NewProc("GetTickCount")
	procWaitNamedPipeW             = modKernel32.NewProc("WaitNamedPipeW")
	procImpersonateNamedPipeClient = modAdvapi32.NewProc("ImpersonateNamedPipeClient")
)

// --- user-mode engine -------------------------------------------------------------------------

func helloKeys() (*helloKey, *helloKey, error) {
	vn, err := passportKeyName(logicalVaultKey)
	if err != nil {
		return nil, nil, err
	}
	pn, err := passportKeyName(logicalPinKey)
	if err != nil {
		return nil, nil, err
	}
	return &helloKey{name: vn, usage: allowDecrypt}, &helloKey{name: pn, usage: allowSigning}, nil
}

func openUserEngine(create bool) (*Engine, error) {
	vk, pk, err := helloKeys()
	if err != nil {
		return nil, err
	}
	e := &Engine{Mode: ModeUser, Root: userVaultDir()}
	st := e.settings()
	if create {
		if err := vk.create("Create the AWS CLI ZSP vault key"); err != nil {
			return nil, fmt.Errorf("create Windows Hello vault key: %w", err)
		}
		if err := pk.create("Create the AWS CLI ZSP account-pin key"); err != nil {
			return nil, fmt.Errorf("create Windows Hello pin key: %w", err)
		}
		if st.QuietBackend == "" {
			if err := tpmCreate(); err == nil {
				st.QuietBackend = "tpm"
			} else {
				fmt.Fprintf(os.Stderr, "No usable TPM for the session cache (%v); falling back to DPAPI.\n", err)
				st.QuietBackend = "dpapi"
			}
			if err := e.saveSettings(st); err != nil {
				return nil, err
			}
		}
	} else if !vk.exists() {
		return nil, errors.New("the vault is not set up yet: run `zsp setup`")
	}
	e.Guarded = &helloSealer{k: *vk}
	e.Pins = &helloPinSigner{k: *pk}
	if st.QuietBackend == "dpapi" {
		e.Quiet = dpapiSealer{}
	} else {
		e.Quiet = tpmSealer{}
	}
	e.Cache = fileCache{e: e}
	e.Probe = Probe{
		Locked: func() (bool, bool) { return localLocked(), true },
		Idle:   localIdle,
	}
	e.Event = eventLogger(false)
	if u, err := user.Current(); err == nil {
		e.Label = u.Username
	}
	e.shipKick = func() { _ = e.ShipNow() }
	return e, e.ensureDirs()
}

// localHelloUnwrap is the client side of the split key: decrypt the user's
// half with the user's own Windows Hello key, in the user's session.
func localHelloUnwrap(blob []byte, prompt string) ([]byte, error) {
	vk, _, err := helloKeys()
	if err != nil {
		return nil, err
	}
	return (&helloSealer{k: *vk}).Unwrap(blob, prompt)
}

func localHelloPublicKey(create bool) (*rsa.PublicKey, error) {
	vk, _, err := helloKeys()
	if err != nil {
		return nil, err
	}
	if create {
		if err := vk.create("Create the AWS CLI ZSP vault key"); err != nil {
			return nil, fmt.Errorf("create Windows Hello vault key: %w", err)
		}
	}
	return vk.publicKey()
}

func deleteHardwareKeys() error {
	return errors.Join(deletePassportKey(logicalVaultKey), deletePassportKey(logicalPinKey), deleteTPMKey())
}

func helloCheck() Check {
	vk, _, err := helloKeys()
	if err != nil {
		return Check{"Windows Hello vault key", false, err.Error(), ""}
	}
	if prov, perr := ncOpenProvider(providerPassport); perr != nil {
		return Check{"Windows Hello vault key", false, "Passport key provider unavailable: " + perr.Error(), "Settings > Accounts > Sign-in options: set up a PIN, face or fingerprint"}
	} else {
		ncFree(prov)
	}
	return Check{"Windows Hello vault key", vk.exists(), "TPM-backed Windows Hello key for this user", "zsp setup"}
}

func platformHealth() []Check {
	var cs []Check
	_, pk, err := helloKeys()
	if err == nil {
		cs = append(cs, Check{"Windows Hello pin key", pk.exists(), "signs account pins", "zsp setup"})
	}
	e := &Engine{Root: userVaultDir()}
	switch e.settings().QuietBackend {
	case "tpm":
		p, h, terr := tpmOpen()
		if terr == nil {
			ncFree(h)
			ncFree(p)
		}
		cs = append(cs, Check{"TPM session key", terr == nil, "Platform Crypto Provider (TPM 2.0)", "zsp setup"})
	case "dpapi":
		cs = append(cs, Check{"TPM session key", false, "no TPM: session cache uses DPAPI (software)", "enable the TPM in firmware, then delete quiet_backend from settings and run zsp setup"})
	}
	return cs
}

// --- prompt ownership & presence ------------------------------------------------------------

func promptOwnerHWND() uintptr {
	if h, _, _ := procGetConsoleWindow.Call(); h != 0 {
		if vis, _, _ := procIsWindowVisible.Call(h); vis != 0 {
			return h
		}
	}
	h, _, _ := procGetForegroundWindow.Call()
	return h
}

func localLocked() bool {
	const desktopSwitchDesktop = 0x0100
	h, _, _ := procOpenInputDesktop.Call(0, 0, desktopSwitchDesktop)
	if h == 0 {
		return true // the secure (lock/UAC) desktop has input
	}
	defer procCloseDesktop.Call(h)
	ok, _, _ := procSwitchDesktop.Call(h)
	return ok == 0
}

func localIdle() (time.Duration, bool) {
	li := struct{ cbSize, dwTime uint32 }{cbSize: 8}
	if r, _, _ := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&li))); r == 0 {
		return 0, false
	}
	now, _, _ := procGetTickCount.Call()
	return time.Duration(uint32(now)-li.dwTime) * time.Millisecond, true
}

// --- processes & callers -----------------------------------------------------------------------

type procInfo struct {
	ppid uint32
	exe  string
}

func processTable() map[uint32]procInfo {
	out := map[uint32]procInfo{}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		out[pe.ProcessID] = procInfo{ppid: pe.ParentProcessID, exe: windows.UTF16ToString(pe.ExeFile[:])}
	}
	return out
}

func processImage(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// processCommandLine uses ProcessCommandLineInformation (Windows 8.1+), which
// needs only PROCESS_QUERY_LIMITED_INFORMATION.
func processCommandLine(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]byte, 8192)
	for i := 0; i < 2; i++ {
		var ret uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &ret)
		if err == nil {
			us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
			if us.Buffer == nil || us.Length == 0 {
				return ""
			}
			// The string lives inside buf; find it by offset.
			off := uintptr(unsafe.Pointer(us.Buffer)) - uintptr(unsafe.Pointer(&buf[0]))
			if off >= uintptr(len(buf)) || off+uintptr(us.Length) > uintptr(len(buf)) {
				return ""
			}
			raw := buf[off : off+uintptr(us.Length)]
			u := make([]uint16, len(raw)/2)
			for j := range u {
				u[j] = uint16(raw[2*j]) | uint16(raw[2*j+1])<<8
			}
			return windows.UTF16ToString(u)
		}
		if ret == 0 || ret > 1<<20 {
			return ""
		}
		buf = make([]byte, ret)
	}
	return ""
}

// fileSigned reports a valid embedded Authenticode signature.
func fileSigned(path string) bool {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p16}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fi),
	}
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return err == nil
}

func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 512<<20)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// callerFromPID describes process pid. full=true also checks the signature and
// hash (needed for remembering callers in service mode).
func callerFromPID(pid uint32, tbl map[uint32]procInfo, full bool) CallerInfo {
	p, ok := tbl[pid]
	if !ok {
		return CallerInfo{Desc: "an exited process"}
	}
	c := CallerInfo{Image: processImage(pid)}
	cmd := processCommandLine(pid)
	if args, err := windows.DecomposeCommandLine(cmd); err == nil {
		c.Args = args
	}
	c.Desc = tidyCommandLine(cmd, p.exe)
	if gp, ok := tbl[p.ppid]; ok {
		c.Desc += " ← " + strings.TrimSuffix(strings.ToLower(gp.exe), ".exe")
	}
	if full && c.Image != "" {
		c.Signed = fileSigned(c.Image)
		if !c.Signed {
			c.Hash = fileHash(c.Image)
		}
	}
	var sess uint32
	if windows.ProcessIdToSessionId(pid, &sess) == nil {
		c.OSSession = sess
	}
	return c
}

func describeCaller() CallerInfo {
	tbl := processTable()
	c := callerFromPID(uint32(os.Getppid()), tbl, false)
	if d, ok := localIdle(); ok {
		c.Idle, c.IdleKnown = d, true
	}
	return c
}

// tidyCommandLine turns `"C:\Program Files\Amazon\AWSCLIV2\aws.exe" s3 ls` into `aws s3 ls`.
func tidyCommandLine(cmd, exe string) string {
	name := strings.TrimSuffix(strings.ToLower(filepath.Base(exe)), ".exe")
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return name
	}
	rest := ""
	if strings.HasPrefix(cmd, `"`) {
		if i := strings.Index(cmd[1:], `"`); i >= 0 {
			rest = cmd[i+2:]
		}
	} else if i := strings.IndexAny(cmd, " \t"); i >= 0 {
		rest = cmd[i:]
	}
	return truncate(strings.TrimSpace(name+" "+strings.TrimSpace(rest)), 160)
}

// --- console input ------------------------------------------------------------------------------

// consoleAsk reads from the console directly (CONIN$), so it works inside
// credential_process where stdin/stdout belong to the AWS CLI. Without a
// console (an IDE plugin), it falls back to a small dialog box.
func consoleAsk(prompt string) (string, error) { return askLine(prompt, false) }

func consoleAskSecret(prompt string) (string, error) { return askLine(prompt, true) }

func askLine(prompt string, secret bool) (string, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return inputBox(prompt)
	}
	defer in.Close()
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		return inputBox(prompt)
	}
	defer out.Close()
	fmt.Fprint(out, prompt)
	if secret {
		h := windows.Handle(in.Fd())
		var mode uint32
		if windows.GetConsoleMode(h, &mode) == nil {
			_ = windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT)
			defer windows.SetConsoleMode(h, mode)
			defer fmt.Fprintln(out)
		}
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func inputBox(prompt string) (string, error) {
	clean := strings.Map(func(r rune) rune {
		if r == '\'' || r == '`' || r == '"' || r == '$' || r < 32 {
			return ' '
		}
		return r
	}, prompt)
	script := `[void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic'); ` +
		`[Microsoft.VisualBasic.Interaction]::InputBox('` + truncate(clean, 300) + `', 'AWS CLI ZSP')`
	out, err := hiddenCmd("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return "", fmt.Errorf("no console to ask on: %w", err)
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "", errors.New("cancelled")
	}
	return s, nil
}

// --- watcher plumbing -------------------------------------------------------------------------------

func waitForChange(dir string, timeout time.Duration) bool {
	const filter = windows.FILE_NOTIFY_CHANGE_FILE_NAME | windows.FILE_NOTIFY_CHANGE_SIZE | windows.FILE_NOTIFY_CHANGE_LAST_WRITE
	h, err := windows.FindFirstChangeNotification(dir, false, filter)
	if err != nil {
		time.Sleep(timeout)
		return false
	}
	defer windows.FindCloseChangeNotification(h)
	ev, _ := windows.WaitForSingleObject(h, uint32(timeout/time.Millisecond))
	return ev == windows.WAIT_OBJECT_0
}

func singleInstance(name string) (func(), bool) {
	n16, _ := windows.UTF16PtrFromString(`Local\` + name)
	h, err := windows.CreateMutex(nil, true, n16)
	if h == 0 {
		return func() {}, true
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(h)
		return func() {}, false
	}
	return func() { windows.CloseHandle(h) }, true
}

func runRoot(allUsers bool) registry.Key {
	if allUsers {
		return registry.LOCAL_MACHINE
	}
	return registry.CURRENT_USER
}

func installAutostart(watcherExe string, allUsers bool) error {
	k, _, err := registry.CreateKey(runRoot(allUsers), runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(runValue, `"`+watcherExe+`" watch`)
}

func removeAutostart(allUsers bool) error {
	k, err := registry.OpenKey(runRoot(allUsers), runKeyPath, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	_ = k.DeleteValue(runValue)
	return nil
}

func autostartInstalled() (string, bool) {
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		if k, err := registry.OpenKey(root, runKeyPath, registry.QUERY_VALUE); err == nil {
			v, _, err := k.GetStringValue(runValue)
			k.Close()
			if err == nil {
				return v, true
			}
		}
	}
	return "", false
}

func hiddenCmd(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return c
}

func startWatcher(exe string) error {
	c := exec.Command(exe, "watch")
	c.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
	if err := c.Start(); err != nil {
		return err
	}
	return c.Process.Release()
}

func mySession() uint32 {
	var s uint32
	_ = windows.ProcessIdToSessionId(uint32(os.Getpid()), &s)
	return s
}

func watcherRunning() bool {
	me := mySession()
	for pid, p := range processTable() {
		if strings.EqualFold(p.exe, "zspw.exe") && pid != uint32(os.Getpid()) {
			var s uint32
			if windows.ProcessIdToSessionId(pid, &s) == nil && s == me {
				return true
			}
		}
	}
	return false
}

func stopWatcher() {
	// taskkill can only end processes this user may end; other users' watchers survive.
	_ = hiddenCmd("taskkill.exe", "/IM", "zspw.exe", "/F", "/FI", "SESSION eq "+fmt.Sprint(mySession())).Run()
}

// userEnvKeys reports AWS key variables persisted in the user environment;
// the AWS CLI prefers them to any profile, which silently bypasses the vault.
func userEnvKeys() []string {
	var out []string
	k, err := registry.OpenKey(registry.CURRENT_USER, "Environment", registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		if _, _, err := k.GetStringValue(v); err == nil {
			out = append(out, v+" (user environment)")
		}
	}
	return out
}

func shellProfileFiles() []string {
	home, _ := os.UserHomeDir()
	docs := filepath.Join(home, "Documents")
	return []string{
		filepath.Join(docs, "PowerShell", "Microsoft.PowerShell_profile.ps1"),
		filepath.Join(docs, "PowerShell", "profile.ps1"),
		filepath.Join(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
		filepath.Join(docs, "WindowsPowerShell", "profile.ps1"),
		filepath.Join(home, ".bashrc"), filepath.Join(home, ".bash_profile"), filepath.Join(home, ".zshrc"),
	}
}

// notify shows a tray balloon via stock PowerShell + WinForms (no extra modules).
func notify(msg string) {
	clean := strings.Map(func(r rune) rune {
		if r == '\'' || r == '`' || r == '"' || r == '$' || r < 32 {
			return -1
		}
		return r
	}, msg)
	script := `Add-Type -AssemblyName System.Windows.Forms; $n = New-Object System.Windows.Forms.NotifyIcon; ` +
		`$n.Icon = [System.Drawing.SystemIcons]::Shield; $n.Visible = $true; ` +
		`$n.ShowBalloonTip(8000, 'AWS CLI ZSP', '` + truncate(clean, 200) + `', 'Info'); Start-Sleep 9; $n.Dispose()`
	_ = hiddenCmd("powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script).Start()
}

// eventLogger writes to the Application log. A non-admin user can write events
// but cannot delete them; clearing the log needs admin and is itself logged.
// The service install registers the source so messages render cleanly.
func eventLogger(_ bool) func(EventLevel, string) {
	l, err := eventlog.Open(eventSource)
	if err != nil {
		return nil
	}
	return func(lvl EventLevel, msg string) {
		switch lvl {
		case EventError:
			_ = l.Error(300, msg)
		case EventWarning:
			_ = l.Warning(200, msg)
		default:
			_ = l.Info(100, msg)
		}
	}
}

// --- service client -----------------------------------------------------------------------------------

// serviceState asks the Service Control Manager (works without admin rights).
func serviceState() (installed, running bool) {
	_, inst, run := servicePID()
	return inst, run
}

func servicePID() (uint32, bool, bool) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, false, false
	}
	defer windows.CloseServiceHandle(m)
	n16, _ := windows.UTF16PtrFromString(serviceName)
	s, err := windows.OpenService(m, n16, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, false, false
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return 0, true, false
	}
	return st.ProcessId, true, st.CurrentState == windows.SERVICE_RUNNING
}

// dialService connects to the broker's pipe and proves the other end is the
// real service: its PID must be the one the Service Control Manager reports.
// A pipe squatter (possible only while the service is down) is refused before
// anything is sent.
func dialService() (io.ReadWriteCloser, error) {
	pid, _, running := servicePID()
	if !running || pid == 0 {
		return nil, errors.New("the AwsCliZsp service is not running")
	}
	n16, _ := windows.UTF16PtrFromString(pipeName)
	var h windows.Handle
	var err error
	for i := 0; i < 50; i++ {
		h, err = windows.CreateFile(n16, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING,
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IMPERSONATION, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("connect to the zsp service: %w", err)
		}
		procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(n16)), 200)
	}
	if err != nil {
		return nil, fmt.Errorf("the zsp service is busy: %w", err)
	}
	var server uint32
	if err := windows.GetNamedPipeServerProcessId(h, &server); err != nil || server != pid {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("REFUSED: the pipe %s is not served by the AwsCliZsp service (pid %d, expected %d)", pipeName, server, pid)
	}
	return os.NewFile(uintptr(h), pipeName), nil
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
