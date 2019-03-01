// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"sync"
)

// buffer provides a linked list buffer for data exchange
// between producer and consumer. Theoretically the buffer is
// of unlimited capacity as it does no allocation of its own.
type buffer struct {
	// protects concurrent access to head, tail and closed
	*sync.Cond

	head *element // the buffer that will be read first
	tail *element // the buffer that will be read last

	closed bool

	bufPool *sync.Pool
}

// An element represents a single link in a linked list.
type element struct {
	pkt  *packetBuf
	next *element
}

// newBuffer returns an empty buffer that is not closed.
func newBuffer() *buffer {
	b := &buffer{
		Cond: newCond(),
		bufPool: &sync.Pool{New: func() interface{} {
			return &packetBuf{buf: make([]byte, 1024*8)}
		}},
	}
	e := &element{pkt:b.bufPool.Get().(*packetBuf)}
	b.head = e
	b.tail = e
	return b
}

// write makes buf available for Read to receive.
// buf must not be modified after the call to write.
func (b *buffer) write(buf []byte) {
	b.Cond.L.Lock()
	pktBuf := b.bufPool.Get().(*packetBuf)
	pktBuf.size = copy(pktBuf.buf, buf)
	e := &element{pkt: pktBuf}
	b.tail.next = e
	b.tail = e
	b.Cond.Signal()
	b.Cond.L.Unlock()
}

// eof closes the buffer. Reads from the buffer once all
// the data has been consumed will receive io.EOF.
func (b *buffer) eof() {
	b.Cond.L.Lock()
	b.closed = true
	b.Cond.Signal()
	b.Cond.L.Unlock()
}

// Read reads data from the internal buffer in buf.  Reads will block
// if no data is available, or until the buffer is closed.
func (b *buffer) Read(buf []byte) (n int, err error) {
	b.Cond.L.Lock()
	defer b.Cond.L.Unlock()

	for len(buf) > 0 {
		// if b.head.pkt != nil {
			// if there is data in b.head, copy it
			if b.head.pkt.size > 0 {
				r := copy(buf, b.head.pkt.buf)
				buf, b.head.pkt.buf = buf[r:], b.head.pkt.buf[r:]
				n += r
				b.head.pkt.size -= r
				continue
			}

			// if there is a next buffer, make it the head
			if b.head.pkt.size == 0 && b.head != b.tail {
				b.bufPool.Put(b.head.pkt)
				b.head = b.head.next
				continue
			}

			// if at least one byte has been copied, return
			if n > 0 {
				break
			}
		// }

		// if nothing was read, and there is nothing outstanding
		// check to see if the buffer is closed.
		if b.closed {
			err = io.EOF
			break
		}
		// out of buffers, wait for producer
		b.Cond.Wait()
	}
	return
}
