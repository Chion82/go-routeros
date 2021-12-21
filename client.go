/*
Package routeros is a pure Go client library for accessing Mikrotik devices using the RouterOS API.
*/
package routeros

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Chion82/go-routeros/proto"
)

const (
	DefaultTimeout = 10 * time.Second
	DefaultDialTimeout = 10 * time.Second
)

// Client is a RouterOS API client.
type Client struct {
	Queue int

	rwc     io.ReadWriteCloser
	r       proto.Reader
	w       proto.Writer
	timeout time.Duration
	closing bool
	async   bool
	nextTag int64
	tags    map[string]sentenceProcessor
	mu      sync.Mutex
}

// NewClient returns a new Client over rwc. Login must be called.
func NewClient(conn net.Conn, timeout time.Duration) (*Client, error) {
	return &Client{
		rwc: conn,
		r:   proto.NewReader(conn, timeout),
		w:   proto.NewWriter(conn, timeout),
		timeout: timeout,
	}, nil
}

// Dial connects and logs in to a RouterOS device.
func Dial(address, username, password string) (*Client, error) {
	return DialWithTimeout(address, username, password, DefaultTimeout)
}

// DialWithTimeout connects and logs in to a RouterOS device.
func DialWithTimeout(address, username, password string, timeout time.Duration) (*Client, error) {
	dialer := net.Dialer{Timeout: DefaultDialTimeout}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return newClientAndLogin(conn, username, password, timeout)
}

// DialTLS connects and logs in to a RouterOS device using TLS.
func DialTLS(address, username, password string, tlsConfig *tls.Config) (*Client, error) {
	return DialTLSWithTimeout(address, username, password, tlsConfig, DefaultTimeout)
}

// DialTLSWithTimeout connects and logs in to a RouterOS device using TLS.
func DialTLSWithTimeout(address, username, password string, tlsConfig *tls.Config, timeout time.Duration) (*Client, error) {
	dialer := net.Dialer{Timeout: DefaultDialTimeout}
	conn, err := tls.DialWithDialer(&dialer, "tcp", address, tlsConfig)
	if err != nil {
		return nil, err
	}
	return newClientAndLogin(conn, username, password, timeout)
}

func newClientAndLogin(conn net.Conn, username, password string, timeout time.Duration) (*Client, error) {
	c, err := NewClient(conn, timeout)
	if err != nil {
		conn.Close()
		return nil, err
	}
	err = c.Login(username, password)
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Close closes the connection to the RouterOS device.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return
	}
	c.closing = true
	c.mu.Unlock()
	c.rwc.Close()
}

// Login runs the /login command. Dial and DialTLS call this automatically.
func (c *Client) Login(username, password string) error {
	r, err := c.Run("/login", "=name="+username, "=password="+password)
	if err != nil {
		return err
	}
	ret, ok := r.Done.Map["ret"]
	if !ok {
		// Login method post-6.43 one stage, cleartext and no challenge
		if r.Done != nil {
			return nil
		}
		return errors.New("RouterOS: /login: no ret (challenge) received")
	}

	// Login method pre-6.43 two stages, challenge
	b, err := hex.DecodeString(ret)
	if err != nil {
		return fmt.Errorf("RouterOS: /login: invalid ret (challenge) hex string received: %s", err)
	}

	r, err = c.Run("/login", "=name="+username, "=response="+c.challengeResponse(b, password))
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) challengeResponse(cha []byte, password string) string {
	h := md5.New()
	h.Write([]byte{0})
	io.WriteString(h, password)
	h.Write(cha)
	return fmt.Sprintf("00%x", h.Sum(nil))
}
