package proto

import (
	"net"
	"sync"
	"time"
)

// Writer writes words to a RouterOS device.
type Writer interface {
	BeginSentence()
	WriteWord(word string)
	EndSentence() error
}

type writer struct {
	net.Conn
	err error
	sync.Mutex
	timeout time.Duration
}

// NewWriter returns a new Writer to write to w.
func NewWriter(w net.Conn, timeout time.Duration) Writer {
	return &writer{
		Conn: w,
		timeout: timeout,
	}
}

// BeginSentence prepares w for writing a sentence.
func (w *writer) BeginSentence() {
	w.Lock()
}

// EndSentence writes the end-of-sentence marker (an empty word).
// It returns the first error that occurred on calls to methods on w.
func (w *writer) EndSentence() error {
	defer w.Unlock()
	w.WriteWord("")
	return w.err
}

// WriteWord writes one word.
func (w *writer) WriteWord(word string) {
	b := []byte(word)
	w.write(encodeLength(len(b)))
	w.write(b)
}

func (w *writer) write(b []byte) {
	if w.err != nil {
		return
	}
	_ = w.SetWriteDeadline(time.Now().Add(w.timeout))
	_, err := w.Write(b)
	if err != nil {
		w.err = err
	}
}

func encodeLength(l int) []byte {
	switch {
	case l < 0x80:
		return []byte{byte(l)}
	case l < 0x4000:
		return []byte{byte(l>>8) | 0x80, byte(l)}
	case l < 0x200000:
		return []byte{byte(l>>16) | 0xC0, byte(l >> 8), byte(l)}
	case l < 0x10000000:
		return []byte{byte(l>>24) | 0xE0, byte(l >> 16), byte(l >> 8), byte(l)}
	default:
		return []byte{0xF0, byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	}
}
