// Package sniproxy passes HTTPS traffic (port 443) straight through to the
// real origin server without terminating TLS: it only peeks at the SNI
// hostname inside the ClientHello to decide where to route, then splices the
// raw TCP streams together.
package sniproxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"smartdns/internal/config"
	"smartdns/internal/resolver"
)

const (
	recordHeaderLen       = 5
	contentTypeHandshake  = 0x16
	handshakeClientHello  = 0x01
	extensionServerName   = 0x0000
	handshakeReadDeadline = 10 * time.Second

	// maxConcurrentConns bounds how many client connections can be relayed
	// at once. Each relayed connection holds two goroutines and buffers for
	// the lifetime of the TCP stream, so without a cap a burst of slow or
	// long-lived connections can drive memory/goroutine count arbitrarily
	// high. Connections beyond the limit are rejected immediately instead
	// of queuing, so the accept loop never blocks.
	maxConcurrentConns = 1000
)

type Proxy struct {
	store *config.Store
	res   *resolver.Resolver
	slots chan struct{}
}

func New(store *config.Store, res *resolver.Resolver) *Proxy {
	return &Proxy{store: store, res: res, slots: make(chan struct{}, maxConcurrentConns)}
}

func (p *Proxy) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}

		select {
		case p.slots <- struct{}{}:
			go p.handle(conn)
		default:
			conn.Close()
		}
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer func() { <-p.slots }()
	defer client.Close()

	cfg := p.store.Get()

	if tcpAddr, ok := client.RemoteAddr().(*net.TCPAddr); ok {
		if !cfg.IsAllowed(tcpAddr.IP) {
			return
		}
	}

	client.SetReadDeadline(time.Now().Add(handshakeReadDeadline))
	br := bufio.NewReader(client)

	sni, raw, err := readClientHelloSNI(br)
	if err != nil || sni == "" {
		return
	}
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	if !cfg.MatchesDomain(sni) {
		return
	}

	ip, err := p.res.ResolveA(sni)
	if err != nil {
		return
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()

	client.SetReadDeadline(time.Time{})

	if _, err := upstream.Write(raw); err != nil {
		return
	}

	pipe(client, upstream, br)
}

// pipe splices client and upstream together until either side closes.
func pipe(client net.Conn, upstream net.Conn, clientReader io.Reader) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(upstream, clientReader)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()

	<-done
	<-done
}

func closeWrite(conn net.Conn) {
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		c.CloseWrite()
	}
}

// readClientHelloSNI consumes exactly one TLS record containing a ClientHello
// from r, returning the SNI hostname and the raw bytes it consumed (so they
// can be replayed verbatim to the real origin server). It only supports the
// common case of an unfragmented ClientHello within a single TLS record.
func readClientHelloSNI(r io.Reader) (sni string, raw []byte, err error) {
	header := make([]byte, recordHeaderLen)
	if _, err = io.ReadFull(r, header); err != nil {
		return "", nil, err
	}
	if header[0] != contentTypeHandshake {
		return "", nil, errors.New("sniproxy: not a TLS handshake record")
	}

	recLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recLen <= 0 || recLen > 1<<16 {
		return "", nil, errors.New("sniproxy: invalid TLS record length")
	}

	body := make([]byte, recLen)
	if _, err = io.ReadFull(r, body); err != nil {
		return "", nil, err
	}

	raw = make([]byte, 0, recordHeaderLen+recLen)
	raw = append(raw, header...)
	raw = append(raw, body...)

	sni, err = parseClientHelloSNI(body)
	return sni, raw, err
}

func parseClientHelloSNI(body []byte) (string, error) {
	if len(body) < 4 || body[0] != handshakeClientHello {
		return "", errors.New("sniproxy: not a client hello")
	}
	pos := 4 // skip handshake type (1) + length (3)

	pos += 2  // client version
	pos += 32 // random
	if pos >= len(body) {
		return "", errors.New("sniproxy: truncated client hello")
	}

	sessIDLen := int(body[pos])
	pos += 1 + sessIDLen
	if pos+2 > len(body) {
		return "", errors.New("sniproxy: truncated client hello")
	}

	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + cipherLen
	if pos+1 > len(body) {
		return "", errors.New("sniproxy: truncated client hello")
	}

	compLen := int(body[pos])
	pos += 1 + compLen
	if pos+2 > len(body) {
		return "", errors.New("sniproxy: no extensions present")
	}

	extTotalLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extTotalLen
	if end > len(body) {
		end = len(body)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(body) {
			break
		}
		if extType == extensionServerName {
			return parseServerName(body[pos : pos+extLen])
		}
		pos += extLen
	}
	return "", errors.New("sniproxy: no SNI extension found")
}

func parseServerName(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("sniproxy: malformed SNI extension")
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	pos := 2
	end := pos + listLen
	if end > len(data) {
		end = len(data)
	}
	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > len(data) {
			break
		}
		if nameType == 0 { // host_name
			return string(data[pos : pos+nameLen]), nil
		}
		pos += nameLen
	}
	return "", errors.New("sniproxy: no host_name in SNI extension")
}
