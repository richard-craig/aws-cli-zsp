package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Broker is the v1.0 service core, platform-neutral so it can be tested
// anywhere. The Windows service (service_windows.go) feeds it connections from
// the named pipe together with an identity it established itself.
//
// Layout under Root (%ProgramData%\aws-cli-zsp, ACL: SYSTEM, Administrators,
// the service account only):
//
//	broker.json             which quiet backend the service uses
//	users\<SID>\hello.pub   the user's Windows Hello public key (enrolment)
//	users\<SID>\keys\...    split-key envelopes
//	users\<SID>\...         pins, phone copies, settings, audit, callers
//
// Sessions live only in memory.
type Broker struct {
	Root  string
	Quiet Sealer
	Event func(EventLevel, string)
	// Lock reports the lock state of a Windows session (WTS). Idle reports the
	// last input age if the OS exposes it to services.
	Lock func(osSession uint32) (bool, bool)
	Idle func(osSession uint32) (time.Duration, bool)

	mu        sync.Mutex
	caches    map[string]*memCache
	bySession map[uint32]map[string]string // os session -> sid -> user label
	kick      chan string
}

// PeerIdentity is what the broker itself established about a pipe client.
type PeerIdentity struct {
	SID           string
	User          string // DOMAIN\name
	OSSession     uint32
	ClientImage   string
	ClientTrusted bool
	Caller        CallerInfo // the program that ran zsp.exe
}

func NewBroker(root string, quiet Sealer) *Broker {
	return &Broker{Root: root, Quiet: quiet, caches: map[string]*memCache{}, bySession: map[uint32]map[string]string{}, kick: make(chan string, 16)}
}

var sidRe = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,14}$`)

func (b *Broker) userRoot(sid string) (string, error) {
	if !sidRe.MatchString(sid) {
		return "", fmt.Errorf("bad SID %q", sid)
	}
	return filepath.Join(b.Root, "users", sid), nil
}

func (b *Broker) cache(sid string) *memCache {
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.caches[sid]
	if c == nil {
		c = newMemCache()
		b.caches[sid] = c
	}
	return c
}

func (b *Broker) engineFor(id PeerIdentity, ui UI) (*Engine, error) {
	root, err := b.userRoot(id.SID)
	if err != nil {
		return nil, err
	}
	e := &Engine{Mode: ModeService, Root: root, Quiet: b.Quiet, Cache: b.cache(id.SID), UI: ui, Caller: id.Caller, Event: b.Event, Label: id.User}
	if err := e.ensureDirs(); err != nil {
		return nil, err
	}
	if pemb, err := os.ReadFile(filepath.Join(root, "hello.pub")); err == nil {
		pub, err := decodePublicKey(string(pemb))
		if err != nil {
			return nil, fmt.Errorf("enrolment record is corrupt: %w", err)
		}
		e.Guarded = &splitSealer{pub: pub, quiet: b.Quiet, ui: ui}
	}
	sess := id.OSSession
	clientIdle, clientIdleKnown := id.Caller.Idle, id.Caller.IdleKnown
	e.Probe = Probe{
		Locked: func() (bool, bool) {
			if b.Lock == nil {
				return false, false
			}
			return b.Lock(sess)
		},
		Idle: func() (time.Duration, bool) {
			if b.Idle != nil {
				if d, ok := b.Idle(sess); ok {
					return d, true
				}
			}
			// Advisory only: the client could lie, but lying "present" only
			// raises a Hello prompt nobody answers; the lock check is authoritative.
			return clientIdle, clientIdleKnown
		},
	}
	sid := id.SID
	e.shipKick = func() {
		select {
		case b.kick <- sid:
		default:
		}
	}
	return e, nil
}

// Handle runs one authenticated request.
func (b *Broker) Handle(id PeerIdentity, req *Request, ui UI) (*Response, error) {
	if !id.ClientTrusted {
		if b.Event != nil {
			b.Event(EventWarning, fmt.Sprintf("refused pipe client %s for %s: not the installed zsp.exe", id.ClientImage, id.User))
		}
		return nil, fmt.Errorf("refused: only the installed zsp.exe (next to the service, in Program Files) may talk to the zsp service; this client is %s", id.ClientImage)
	}
	// The broker's own view of the caller wins; keep only the client's idle report.
	caller := id.Caller
	caller.Idle, caller.IdleKnown = req.Caller.Idle, req.Caller.IdleKnown
	caller.OSSession = id.OSSession
	id.Caller = caller
	req.Caller = caller

	b.mu.Lock()
	if b.bySession[id.OSSession] == nil {
		b.bySession[id.OSSession] = map[string]string{}
	}
	b.bySession[id.OSSession][id.SID] = id.User
	b.mu.Unlock()

	if req.Op == "enroll" {
		return &Response{}, b.enroll(id, req.Args["pub"], ui)
	}
	e, err := b.engineFor(id, ui)
	if err != nil {
		return nil, err
	}
	return dispatch(e, req)
}

func (b *Broker) enroll(id PeerIdentity, pubPEM string, ui UI) error {
	pub, err := decodePublicKey(pubPEM)
	if err != nil {
		return err
	}
	e, err := b.engineFor(id, ui)
	if err != nil {
		return err
	}
	path := filepath.Join(e.Root, "hello.pub")
	if old, err := os.ReadFile(path); err == nil {
		if strings.TrimSpace(string(old)) == strings.TrimSpace(pubPEM) {
			return nil // already enrolled with this key
		}
		if len(e.profiles()) > 0 {
			// Re-enrolling would let whoever holds the new key open these
			// envelopes' Hello half. Only an administrator may reset a user.
			e.Audit("enroll-refused", "", false, "a different Windows Hello key tried to enrol", id.Caller.Desc)
			return errors.New("this user is already enrolled with a different Windows Hello key and has keys in the vault. If you reset Windows Hello, an administrator must run `zsp service reset-user` (your sealed keys cannot be recovered; create new ones in IAM)")
		}
	}
	if err := writeFileAtomic(path, []byte(encodePublicKey(pub)), 0o600); err != nil {
		return err
	}
	e.Audit("enrolled", "", true, "Windows Hello key registered with the service", id.Caller.Desc)
	return nil
}

// OnLock clears Hello sessions of every user seen in the locked Windows session.
func (b *Broker) OnLock(osSession uint32) {
	b.mu.Lock()
	users := map[string]string{}
	for sid, u := range b.bySession[osSession] {
		users[sid] = u
	}
	b.mu.Unlock()
	for sid, u := range users {
		if e, err := b.engineFor(PeerIdentity{SID: sid, User: u, OSSession: osSession}, nil); err == nil {
			e.clearOnLock()
		}
	}
}

// ShipLoop ships every user's audit trail every five minutes, and promptly
// after a refusal.
func (b *Broker) ShipLoop(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	shipOne := func(sid string) {
		root, err := b.userRoot(sid)
		if err != nil {
			return
		}
		e := &Engine{Mode: ModeService, Root: root, Quiet: b.Quiet, Event: b.Event, Label: sid}
		if e.settings().Ship == nil {
			return
		}
		if err := e.ShipNow(); err != nil && b.Event != nil {
			b.Event(EventWarning, "audit shipping for "+sid+" failed: "+err.Error())
		}
	}
	for {
		select {
		case <-stop:
			return
		case sid := <-b.kick:
			shipOne(sid)
		case <-t.C:
			dirs, _ := os.ReadDir(filepath.Join(b.Root, "users"))
			for _, d := range dirs {
				if d.IsDir() {
					shipOne(d.Name())
				}
			}
		}
	}
}

// ResetUser removes a user's enrolment and vault (administrator only).
func (b *Broker) ResetUser(sid string) error {
	root, err := b.userRoot(sid)
	if err != nil {
		return err
	}
	b.mu.Lock()
	if c := b.caches[sid]; c != nil {
		c.Remove("", anySession)
	}
	b.mu.Unlock()
	if _, err := os.Stat(root); err != nil {
		return fmt.Errorf("no vault for %s", sid)
	}
	return os.Rename(root, root+".reset-"+time.Now().UTC().Format("20060102T150405Z"))
}
