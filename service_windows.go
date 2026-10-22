//go:build windows

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// v1.0 broker service.

const virtualAccount = `NT SERVICE\` + serviceName

func programDataRoot() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "aws-cli-zsp")
}

func serviceExePath() string { return filepath.Join(programFilesDir(), "zsp.exe") }

func programFilesDir() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "aws-cli-zsp")
}

// --- install / uninstall ------------------------------------------------------------------------

func cmdServiceInstall(account string) error {
	if !isElevated() {
		return errors.New("installing the service needs an elevated terminal (Run as administrator)")
	}
	if account == "" {
		account = virtualAccount
	}
	if !strings.EqualFold(account, virtualAccount) && !strings.EqualFold(account, "LocalSystem") {
		return errors.New("--service-account must be LocalSystem (default is the virtual account " + virtualAccount + ")")
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// Upgrade in place if it already exists.
	existing, err := m.OpenService(serviceName)
	if err == nil {
		fmt.Println("Service exists: stopping it to upgrade the binaries...")
		_, _ = existing.Control(svc.Stop)
		waitState(existing, svc.Stopped, 20*time.Second)
	}

	// Watchers of every signed-in user hold zspw.exe open; stop them for the copy.
	// They come back at each user's next sign-in (or `zsp setup`).
	_ = hiddenCmd("taskkill.exe", "/IM", "zspw.exe", "/F").Run()
	exe, _ := os.Executable()
	src := filepath.Dir(exe)
	dst := programFilesDir()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, n := range []string{"zsp.exe", "zspw.exe"} {
		if err := copyFile(filepath.Join(src, n), filepath.Join(dst, n)); err != nil {
			return fmt.Errorf("copy %s (keep zsp.exe and zspw.exe together): %w", n, err)
		}
	}
	svcExe := filepath.Join(dst, "zsp.exe")

	if existing == nil {
		cfg := mgr.Config{
			ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
			StartType:        mgr.StartAutomatic,
			ErrorControl:     mgr.ErrorNormal,
			DisplayName:      "AWS CLI ZSP broker",
			Description:      "Holds sealed AWS access keys and issues short STS sessions to the AWS CLI after Windows Hello approval (aws-cli-zsp).",
			ServiceStartName: account,
			SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		}
		if strings.EqualFold(account, "LocalSystem") {
			cfg.ServiceStartName = ""
		}
		s, err := m.CreateService(serviceName, svcExe, cfg, "service-run")
		if err != nil {
			return fmt.Errorf("create service: %w", err)
		}
		existing = s
		_ = s.SetRecoveryActions([]mgr.RecoveryAction{
			{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
			{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
		}, 86400)
	}
	defer existing.Close()

	cfg, err := existing.Config()
	if err != nil {
		return err
	}
	if err := secureDataDir(programDataRoot(), cfg.ServiceStartName); err != nil {
		return fmt.Errorf("secure %s: %w", programDataRoot(), err)
	}
	if err := eventlog.InstallAsEventCreate(eventSource, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil &&
		!strings.Contains(err.Error(), "exists") {
		fmt.Fprintln(os.Stderr, "warning: event source not registered:", err)
	}
	// Watcher for every user (moves new plaintext keys into the service, repairs wiring).
	if err := installAutostart(filepath.Join(dst, "zspw.exe"), true); err != nil {
		return err
	}
	if err := existing.Start(); err != nil && !strings.Contains(err.Error(), "already running") {
		return fmt.Errorf("start service: %w", err)
	}
	if !waitState(existing, svc.Running, 20*time.Second) {
		return errors.New("the service did not reach Running; check Event Viewer > Application > aws-cli-zsp")
	}
	fmt.Printf("Service %s is running as %s.\n  binaries: %s\n  vault:    %s\n\n", serviceName, orDash(cfg.ServiceStartName), dst, programDataRoot())
	fmt.Printf("Next, as each normal (non-elevated) user:\n  \"%s\" setup            (new users)\n  \"%s\" service migrate  (users with a user-mode vault)\n", svcExe, svcExe)
	return nil
}

func waitState(s *mgr.Service, want svc.State, d time.Duration) bool {
	return waitUntil(d, func() bool {
		st, err := s.Query()
		return err == nil && st.State == want
	})
}

// secureDataDir creates %ProgramData%\aws-cli-zsp owned by Administrators with a
// protected DACL: SYSTEM, Administrators and the service account only. A folder
// pre-created by someone else (squatting) is moved aside first.
func secureDataDir(dir, account string) error {
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		ok := false
		if err == nil {
			if owner, _, err := sd.Owner(); err == nil {
				ok = owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)
			}
		}
		if !ok {
			aside := dir + ".suspect-" + time.Now().Format("20060102T150405")
			fmt.Fprintf(os.Stderr, "warning: %s existed and was not owned by Administrators; moved to %s\n", dir, aside)
			if err := os.Rename(dir, aside); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "users"), 0o700); err != nil {
		return err
	}
	svcSID := "SY"
	if account != "" && !strings.EqualFold(account, "LocalSystem") {
		sid, _, _, err := windows.LookupSID("", account)
		if err != nil {
			return fmt.Errorf("look up %s: %w", account, err)
		}
		svcSID = sid.String()
	}
	sddl := "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + svcSID + ")"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

func sealedKeyCount(root string) int {
	n := 0
	users, _ := os.ReadDir(filepath.Join(root, "users"))
	for _, u := range users {
		keys, _ := os.ReadDir(filepath.Join(root, "users", u.Name(), "keys"))
		for _, k := range keys {
			if strings.HasSuffix(k.Name(), ".sealed") {
				n++
			}
		}
	}
	return n
}

func cmdServiceUninstall(purge bool) error {
	if !isElevated() {
		return errors.New("uninstalling the service needs an elevated terminal (Run as administrator)")
	}
	root := programDataRoot()
	if n := sealedKeyCount(root); n > 0 && !purge {
		return fmt.Errorf("refusing: %d key(s) are still sealed in the service. Each user should first run `zsp restore --profile <name>` (or pass --purge to DESTROY them; they can be recreated in IAM)", n)
	}
	if purge {
		fmt.Print("Type DELETE to destroy every sealed key and the service audit trail: ")
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(ans) != "DELETE" {
			return errors.New("not confirmed")
		}
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		_, _ = s.Control(svc.Stop)
		waitState(s, svc.Stopped, 20*time.Second)
		if err := s.Delete(); err != nil {
			s.Close()
			return err
		}
		s.Close()
	}
	_ = eventlog.Remove(eventSource)
	_ = removeAutostart(true)
	if purge {
		if err := os.RemoveAll(root); err != nil {
			return err
		}
	}
	fmt.Printf("Service removed. Binaries remain in %s (delete the folder when no terminal is using them).\n", programFilesDir())
	return nil
}

func cmdServiceResetUser(sid string) error {
	if !isElevated() {
		return errors.New("reset-user needs an elevated terminal")
	}
	if sid == "" {
		return errors.New("usage: zsp service reset-user --sid S-1-5-21-...  (find it with: whoami /user)")
	}
	b := NewBroker(programDataRoot(), nil)
	if err := b.ResetUser(sid); err != nil {
		return err
	}
	// Restart so no cached session of that user survives.
	if m, err := mgr.Connect(); err == nil {
		defer m.Disconnect()
		if s, err := m.OpenService(serviceName); err == nil {
			_, _ = s.Control(svc.Stop)
			waitState(s, svc.Stopped, 20*time.Second)
			_ = s.Start()
			s.Close()
		}
	}
	fmt.Printf("Vault for %s moved aside and service restarted. The user can now run `zsp setup` again.\n", sid)
	return nil
}

// --- running as the service ------------------------------------------------------------------------

func cmdServiceRun() error {
	is, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !is {
		return errors.New("service-run is started by the Service Control Manager")
	}
	return svc.Run(serviceName, &brokerService{})
}

type brokerService struct{}

type brokerConfig struct {
	QuietBackend string `json:"quiet_backend"`
}

func (s *brokerService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	elog := eventLogger(true)
	logf := func(lvl EventLevel, f string, a ...any) {
		if elog != nil {
			elog(lvl, fmt.Sprintf(f, a...))
		}
	}
	root := programDataRoot()
	if err := os.MkdirAll(filepath.Join(root, "users"), 0o700); err != nil {
		logf(EventError, "cannot create %s: %v", root, err)
		return true, 1
	}
	quiet, backend := brokerQuietSealer(root)
	b := NewBroker(root, quiet)
	b.Event = elog
	b.Lock = wtsLocked
	b.Idle = wtsIdle
	stop := make(chan struct{})
	go pipeServer(b, stop, logf)
	go b.ShipLoop(stop)
	logf(EventInfo, "aws-cli-zsp broker %s started (key backend %s)", version_, backend)

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			close(stop)
			logf(EventInfo, "aws-cli-zsp broker stopping; in-memory sessions discarded")
			return false, 0
		case svc.SessionChange:
			const wtsSessionLogoff, wtsSessionLock = 6, 7
			if (c.EventType == wtsSessionLock || c.EventType == wtsSessionLogoff) && c.EventData != 0 {
				n := (*windows.WTSSESSION_NOTIFICATION)(osPointer(c.EventData))
				b.OnLock(n.SessionID)
			}
		}
	}
	return false, 0
}

// brokerQuietSealer picks the service's own key: TPM if the service account can
// use the Platform Crypto Provider, otherwise DPAPI under the service account.
// The choice is remembered so envelopes stay readable.
func brokerQuietSealer(root string) (Sealer, string) {
	path := filepath.Join(root, "broker.json")
	var cfg brokerConfig
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	if cfg.QuietBackend == "" {
		cfg.QuietBackend = "dpapi"
		if err := tpmCreate(); err == nil {
			if _, err := (tpmSealer{}).Wrap(make([]byte, 32)); err == nil {
				cfg.QuietBackend = "tpm"
			}
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		_ = writeFileAtomic(path, b, 0o600)
	}
	if cfg.QuietBackend == "tpm" {
		return tpmSealer{}, "tpm"
	}
	return dpapiSealer{}, "dpapi"
}

// --- the named pipe ----------------------------------------------------------------------------------

// Pipe DACL: deny network logons, full control for SYSTEM and Administrators,
// read/write for authenticated local users. Identity is then established per
// connection from the client's token; access to a vault is by SID.
const pipeSDDL = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"

func pipeServer(b *Broker, stop <-chan struct{}, logf func(EventLevel, string, ...any)) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		logf(EventError, "pipe security descriptor: %v", err)
		return
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	n16, _ := windows.UTF16PtrFromString(pipeName)
	first := true
	for {
		select {
		case <-stop:
			return
		default:
		}
		flags := uint32(windows.PIPE_ACCESS_DUPLEX)
		if first {
			flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE // refuse if someone squatted the name
		}
		h, err := windows.CreateNamedPipe(n16, flags,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
			windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, sa)
		if err != nil {
			logf(EventError, "CreateNamedPipe: %v", err)
			if first {
				return // the name is taken by someone else: never serve beside a squatter
			}
			time.Sleep(time.Second)
			continue
		}
		first = false
		if err := windows.ConnectNamedPipe(h, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			windows.CloseHandle(h)
			continue
		}
		go handlePipeConn(b, h, logf)
	}
}

func handlePipeConn(b *Broker, h windows.Handle, logf func(EventLevel, string, ...any)) {
	defer func() {
		if r := recover(); r != nil {
			logf(EventError, "pipe handler panic: %v", r)
		}
	}()
	id, err := identifyClient(h)
	f := os.NewFile(uintptr(h), pipeName)
	defer f.Close()
	if err != nil {
		logf(EventWarning, "pipe client could not be identified: %v", err)
		w := newWire(f)
		_ = w.send(wireMsg{T: "error", Err: "could not identify the caller: " + err.Error()})
		return
	}
	// A request that waits on a person (Hello, MFA code) gets five minutes.
	watchdog := time.AfterFunc(5*time.Minute, func() { _ = windows.DisconnectNamedPipe(h) })
	defer watchdog.Stop()
	serveConn(f, func(req *Request, ui UI) (*Response, error) { return b.Handle(id, req, ui) })
	_ = windows.FlushFileBuffers(h)
	_ = windows.DisconnectNamedPipe(h)
}

// identifyClient establishes who is on the other end, while impersonating them
// (so process inspection runs with the user's own rights, not the service's).
func identifyClient(h windows.Handle) (PeerIdentity, error) {
	var id PeerIdentity
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
		return id, err
	}
	runtime.LockOSThread()
	if r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h)); r == 0 {
		runtime.UnlockOSThread()
		return id, fmt.Errorf("impersonate: %v", e)
	}
	reverted := false
	defer func() {
		if !reverted {
			// Could not drop the client's identity: never let this OS thread run
			// anything else. Exiting a goroutine while locked kills the thread.
			return
		}
		runtime.UnlockOSThread()
	}()

	var tok windows.Token
	err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
	if err == nil {
		if tu, err2 := tok.GetTokenUser(); err2 == nil {
			id.SID = tu.User.Sid.String()
			if acct, dom, _, err3 := tu.User.Sid.LookupAccount(""); err3 == nil {
				id.User = dom + `\` + acct
			}
		}
		var sess, n uint32
		if windows.GetTokenInformation(tok, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sess)), 4, &n) == nil {
			id.OSSession = sess
		}
		tok.Close()
	}
	tbl := processTable()
	id.ClientImage = processImage(pid)
	if p, ok := tbl[pid]; ok {
		id.Caller = callerFromPID(p.ppid, tbl, true)
	}
	if windows.RevertToSelf() == nil {
		reverted = true
	} else {
		return id, errors.New("could not drop the client's identity")
	}
	if err != nil {
		return id, err
	}
	if id.SID == "" {
		return id, errors.New("no user SID on the client token")
	}
	self, _ := os.Executable()
	dir := filepath.Dir(self)
	for _, n := range []string{"zsp.exe", "zspw.exe"} {
		if strings.EqualFold(filepath.Clean(id.ClientImage), filepath.Join(dir, n)) {
			id.ClientTrusted = true
		}
	}
	if id.User == "" {
		id.User = id.SID
	}
	return id, nil
}

// --- WTS: lock state and idle time of a Windows session -----------------------------------------------

var (
	modWtsapi32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = modWtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = modWtsapi32.NewProc("WTSFreeMemory")
)

// wtsInfoEx returns WTSINFOEX_LEVEL1_W fields we need: SessionFlags,
// LastInputTime, CurrentTime. Offsets: Level DWORD, then the union aligned to 8;
// in LEVEL1, SessionFlags is at +8 and the LARGE_INTEGER times start at +160.
func wtsInfoEx(session uint32) (flags int32, lastInput, current int64, ok bool) {
	const wtsSessionInfoEx = 25
	var buf uintptr
	var n uint32
	r, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(session), wtsSessionInfoEx, uintptr(unsafe.Pointer(&buf)), uintptr(unsafe.Pointer(&n)))
	if r == 0 || buf == 0 {
		return 0, 0, 0, false
	}
	defer procWTSFreeMemory.Call(buf)
	if n < 8+200 {
		return 0, 0, 0, false
	}
	raw := unsafe.Slice((*byte)(osPointer(buf)), n)
	level := *(*uint32)(unsafe.Pointer(&raw[0]))
	if level != 1 {
		return 0, 0, 0, false
	}
	d := raw[8:]
	flags = *(*int32)(unsafe.Pointer(&d[8]))
	lastInput = *(*int64)(unsafe.Pointer(&d[184]))
	current = *(*int64)(unsafe.Pointer(&d[192]))
	return flags, lastInput, current, true
}

func wtsLocked(session uint32) (bool, bool) {
	const wtsSessionStateLock, wtsSessionStateUnlock = 0, 1
	flags, _, _, ok := wtsInfoEx(session)
	if !ok {
		return false, false
	}
	switch flags {
	case wtsSessionStateLock:
		return true, true
	case wtsSessionStateUnlock:
		return false, true
	}
	return false, false
}

func wtsIdle(session uint32) (time.Duration, bool) {
	_, last, cur, ok := wtsInfoEx(session)
	if !ok || last == 0 || cur == 0 || cur < last {
		return 0, false // console sessions often do not report it; the client's report is used instead
	}
	return time.Duration(cur-last) * 100, true
}

// osPointer turns an address handed to us by Windows (memory Go does not
// manage) into a pointer without tripping the unsafeptr vet check.
func osPointer(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}
