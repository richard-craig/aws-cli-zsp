package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Wire protocol between zsp.exe and the broker service: newline-delimited JSON
// over the named pipe. One request per connection. While the broker works on
// it, it may call back into the client (print a line, ask a question, or ask
// for a Windows Hello unwrap of the user's key half) before the final result.
//
//   client -> {"t":"req", "req":{...}}
//   broker -> {"t":"print","text":...} | {"t":"ask","text":...} | {"t":"hello","text":prompt,"blob":k1}
//   client -> {"t":"reply","text":answer} | {"t":"reply","blob":k1} | {"t":"reply","err":"cancelled"}
//   broker -> {"t":"result","resp":{...}} | {"t":"error","err":...}

type wireMsg struct {
	T    string    `json:"t"`
	Req  *Request  `json:"req,omitempty"`
	Text string    `json:"text,omitempty"`
	Blob []byte    `json:"blob,omitempty"`
	Resp *Response `json:"resp,omitempty"`
	Err  string    `json:"err,omitempty"`
}

const maxConnBytes = 8 << 20

type wire struct {
	dec *json.Decoder
	enc *json.Encoder
	mu  sync.Mutex
}

func newWire(rw io.ReadWriter) *wire {
	return &wire{dec: json.NewDecoder(io.LimitReader(rw, maxConnBytes)), enc: json.NewEncoder(rw)}
}

func (w *wire) send(m wireMsg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(m)
}

func (w *wire) recv() (wireMsg, error) {
	var m wireMsg
	err := w.dec.Decode(&m)
	return m, err
}

// remoteUI implements UI by calling back to the connected client.
type remoteUI struct{ w *wire }

func (u *remoteUI) Printf(format string, a ...any) {
	_ = u.w.send(wireMsg{T: "print", Text: fmt.Sprintf(format, a...)})
}

func (u *remoteUI) reply(m wireMsg) (wireMsg, error) {
	if err := u.w.send(m); err != nil {
		return wireMsg{}, err
	}
	r, err := u.w.recv()
	if err != nil {
		return wireMsg{}, fmt.Errorf("client went away: %w", err)
	}
	if r.T != "reply" {
		return wireMsg{}, fmt.Errorf("protocol error: expected reply, got %q", r.T)
	}
	if r.Err != "" {
		return wireMsg{}, errors.New(r.Err)
	}
	return r, nil
}

func (u *remoteUI) Ask(prompt string) (string, error) {
	r, err := u.reply(wireMsg{T: "ask", Text: prompt})
	return r.Text, err
}

func (u *remoteUI) HelloUnwrap(blob []byte, prompt string) ([]byte, error) {
	r, err := u.reply(wireMsg{T: "hello", Text: prompt, Blob: blob})
	return r.Blob, err
}

// serveConn runs one request on the broker side.
func serveConn(rw io.ReadWriter, handle func(req *Request, ui UI) (*Response, error)) {
	w := newWire(rw)
	m, err := w.recv()
	if err != nil || m.T != "req" || m.Req == nil {
		_ = w.send(wireMsg{T: "error", Err: "protocol error: expected a request"})
		return
	}
	resp, err := handle(m.Req, &remoteUI{w: w})
	if err != nil {
		_ = w.send(wireMsg{T: "error", Err: err.Error()})
		return
	}
	_ = w.send(wireMsg{T: "result", Resp: resp})
}

// clientRoundTrip runs one request on the client side, answering callbacks with ui.
func clientRoundTrip(rw io.ReadWriter, req *Request, ui UI) (*Response, error) {
	w := newWire(rw)
	if err := w.send(wireMsg{T: "req", Req: req}); err != nil {
		return nil, fmt.Errorf("send to zsp service: %w", err)
	}
	for {
		m, err := w.recv()
		if err != nil {
			return nil, fmt.Errorf("zsp service closed the connection: %w", err)
		}
		switch m.T {
		case "print":
			ui.Printf("%s", m.Text)
		case "ask":
			ans, err := ui.Ask(m.Text)
			r := wireMsg{T: "reply", Text: ans}
			if err != nil {
				r = wireMsg{T: "reply", Err: err.Error()}
			}
			if err := w.send(r); err != nil {
				return nil, err
			}
		case "hello":
			k1, err := ui.HelloUnwrap(m.Blob, m.Text)
			r := wireMsg{T: "reply", Blob: k1}
			if err != nil {
				r = wireMsg{T: "reply", Err: err.Error()}
			}
			err2 := w.send(r)
			zero(k1)
			if err2 != nil {
				return nil, err2
			}
		case "result":
			if m.Resp == nil {
				m.Resp = &Response{}
			}
			return m.Resp, nil
		case "error":
			return nil, errors.New(m.Err)
		default:
			return nil, fmt.Errorf("protocol error: unexpected %q", m.T)
		}
	}
}
