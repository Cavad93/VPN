// Package transport — mux.go implements stream multiplexing over a single
// net.Conn. Multiple independent virtual Streams share one underlying
// byte-stream connection without interfering with each other.
//
// The initiator (isClient=true) uses even stream IDs (2, 4, 6, …) and the
// responder uses odd stream IDs (1, 3, 5, …), so both sides can open streams
// concurrently without collision.
//
// Wire format of one mux frame:
//
//	bytes 0-3  — stream ID   (uint32, big-endian)
//	byte  4    — frame type  (FrameSYN / FrameData / FrameFIN)
//	bytes 5-6  — payload length (uint16, big-endian, 0…65535)
//	bytes 7-N  — payload
package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// muxFramePool holds pre-allocated frame buffers sized for typical MTU traffic
// (muxHeaderSize + 1500 bytes). Buffers for oversized payloads are allocated
// directly and not pooled to avoid holding large memory across goroutines.
var muxFramePool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, muxHeaderSize+1500)
		return &buf
	},
}

// Frame types carried in the mux header.
const (
	FrameSYN  uint8 = 0x01 // open a new stream
	FrameData uint8 = 0x02 // data payload
	FrameFIN  uint8 = 0x03 // half-close stream from sender
)

// muxHeaderSize is the fixed size of the mux frame header in bytes.
// Layout: streamID(4) + type(1) + length(2) = 7 bytes.
const muxHeaderSize = 7

// maxMuxPayload is the maximum payload bytes per single mux frame (uint16 max).
const maxMuxPayload = 0xFFFF

// Mux multiplexes multiple Streams over a single net.Conn.
// All public methods are safe for concurrent use from multiple goroutines.
type Mux struct {
	conn      net.Conn
	writeMu   sync.Mutex  // serialises frame writes
	streamsMu sync.Mutex  // protects streams and nextID
	streams   map[uint32]*Stream
	acceptCh  chan *Stream
	nextID    uint32 // next local stream ID; incremented by 2
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// NewMux wraps conn as a multiplexed transport. isClient controls which stream
// ID namespace is used for locally-opened streams:
//   - client (isClient=true)  → even IDs: 2, 4, 6, …
//   - server (isClient=false) → odd  IDs: 1, 3, 5, …
//
// The caller must not use conn directly after calling NewMux.
func NewMux(conn net.Conn, isClient bool) *Mux {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Mux{
		conn:     conn,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, 64),
		ctx:      ctx,
		cancel:   cancel,
	}
	if isClient {
		m.nextID = 2
	} else {
		m.nextID = 1
	}
	go m.readLoop()
	return m
}

// OpenStream creates a new outbound Stream and sends a SYN frame to the peer.
// It returns an error if the underlying connection is already closed.
func (m *Mux) OpenStream() (*Stream, error) {
	m.streamsMu.Lock()
	id := m.nextID
	m.nextID += 2
	s := newStream(id, m)
	m.streams[id] = s
	m.streamsMu.Unlock()

	if err := m.writeFrame(id, FrameSYN, nil); err != nil {
		m.streamsMu.Lock()
		delete(m.streams, id)
		m.streamsMu.Unlock()
		s.closeLocal()
		return nil, err
	}
	return s, nil
}

// AcceptStream blocks until the remote peer opens a new stream, ctx is
// cancelled, or the Mux is closed.
func (m *Mux) AcceptStream(ctx context.Context) (*Stream, error) {
	select {
	case s, ok := <-m.acceptCh:
		if !ok {
			return nil, errors.New("mux: closed")
		}
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.ctx.Done():
		return nil, errors.New("mux: connection closed")
	}
}

// Close shuts down all Streams and the underlying connection.
// Lock ordering: streamsMu must NOT be held while calling closeLocal, because
// Stream.Close holds closeOnce while acquiring streamsMu. Snapshot the stream
// list first, clear the map, then close streams without holding streamsMu to
// prevent an ABBA deadlock with concurrent Stream.Close calls.
// UnderlyingConn returns the net.Conn wrapped by this Mux.
// Used by the perf subsystem to poll OS-level TCP metrics (TCP_INFO).
func (m *Mux) UnderlyingConn() net.Conn {
	return m.conn
}

func (m *Mux) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.cancel()
		m.streamsMu.Lock()
		toClose := make([]*Stream, 0, len(m.streams))
		for _, s := range m.streams {
			toClose = append(toClose, s)
		}
		m.streams = make(map[uint32]*Stream)
		m.streamsMu.Unlock()

		for _, s := range toClose {
			s.closeLocal()
		}
		err = m.conn.Close()
	})
	return err
}

// writeFrame serialises and sends a single mux frame. Thread-safe.
// Header and payload are concatenated into one slice before writing so that
// the underlying NoiseConn encrypts them as a single message. This is
// required for the Python client which expects one read_message() call to
// return the complete frame (header + payload).
//
// Optimisation: frames ≤ muxHeaderSize+1500 bytes are built from a sync.Pool
// buffer, avoiding a heap allocation on every IP packet write.
func (m *Mux) writeFrame(streamID uint32, fType uint8, payload []byte) error {
	need := muxHeaderSize + len(payload)

	var frame []byte
	var poolBuf *[]byte
	if need <= muxHeaderSize+1500 {
		poolBuf = muxFramePool.Get().(*[]byte)
		frame = (*poolBuf)[:need]
	} else {
		frame = make([]byte, need)
	}

	binary.BigEndian.PutUint32(frame[0:4], streamID)
	frame[4] = fType
	binary.BigEndian.PutUint16(frame[5:7], uint16(len(payload)))
	copy(frame[muxHeaderSize:], payload)

	m.writeMu.Lock()
	_, err := m.conn.Write(frame)
	m.writeMu.Unlock()

	if poolBuf != nil {
		muxFramePool.Put(poolBuf)
	}
	return err
}

// readLoop reads frames from the underlying connection and dispatches them to
// the appropriate Stream. It runs as a dedicated goroutine until an I/O error
// (including a deliberate Close) terminates the connection.
func (m *Mux) readLoop() {
	hdr := make([]byte, muxHeaderSize)
	for {
		if _, err := io.ReadFull(m.conn, hdr); err != nil {
			m.Close() //nolint:errcheck
			return
		}
		streamID := binary.BigEndian.Uint32(hdr[0:4])
		fType := hdr[4]
		length := binary.BigEndian.Uint16(hdr[5:7])

		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(m.conn, payload); err != nil {
				m.Close() //nolint:errcheck
				return
			}
		}

		m.streamsMu.Lock()
		s, exists := m.streams[streamID]
		m.streamsMu.Unlock()

		switch fType {
		case FrameSYN:
			if !exists {
				s = newStream(streamID, m)
				m.streamsMu.Lock()
				m.streams[streamID] = s
				m.streamsMu.Unlock()
				select {
				case m.acceptCh <- s:
				default:
					// Accept backlog full — reject the stream.
					s.closeLocal()
					m.streamsMu.Lock()
					delete(m.streams, streamID)
					m.streamsMu.Unlock()
				}
			}

		case FrameData:
			if exists {
				// payload is a fresh allocation from readLoop — pass it directly,
				// no extra copy needed.
				select {
				case s.readCh <- payload:
				default:
					// Receive buffer full — drop the frame.
					// The upper layer is responsible for flow control.
				}
			}

		case FrameFIN:
			if exists {
				s.remoteOnce.Do(func() {
					close(s.remoteClosed)
				})
				m.streamsMu.Lock()
				delete(m.streams, streamID)
				m.streamsMu.Unlock()
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

// Stream is a virtual bidirectional channel within a Mux.
// It implements io.ReadWriteCloser.
type Stream struct {
	id           uint32
	mux          *Mux
	readCh       chan []byte   // inbound payloads queued by readLoop
	readBuf      []byte       // leftover bytes from the last readCh entry
	remoteClosed chan struct{} // closed when the remote sends FIN
	remoteOnce   sync.Once
	closed       chan struct{} // closed when Close/closeLocal is called
	closeOnce    sync.Once
}

func newStream(id uint32, mux *Mux) *Stream {
	return &Stream{
		id:           id,
		mux:          mux,
		readCh:       make(chan []byte, 8192), // large buffer avoids drops (non-blocking dispatch)
		remoteClosed: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

// ID returns the stream's numeric identifier.
func (s *Stream) ID() uint32 { return s.id }

// Write sends p over the stream. Large payloads are automatically fragmented
// into maxMuxPayload-sized frames. Returns an error if the stream is closed.
func (s *Stream) Write(p []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, errors.New("mux: stream closed")
	default:
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxMuxPayload {
			chunk = p[:maxMuxPayload]
		}
		if err := s.mux.writeFrame(s.id, FrameData, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read reads data from the stream into p. It blocks until data is available,
// the remote sends FIN (returns io.EOF), or the stream is closed locally.
// Bytes that do not fit into p are buffered for the next call.
func (s *Stream) Read(p []byte) (int, error) {
	// Return any buffered tail from a previous partial read first.
	if len(s.readBuf) > 0 {
		n := copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}
	// Non-blocking drain: prioritise already-queued data.
	select {
	case data := <-s.readCh:
		return s.consumeData(p, data), nil
	default:
	}
	// Block until data arrives, remote closes, or local close.
	select {
	case data := <-s.readCh:
		return s.consumeData(p, data), nil
	case <-s.remoteClosed:
		// One final drain to deliver any frames that arrived before FIN.
		select {
		case data := <-s.readCh:
			return s.consumeData(p, data), nil
		default:
			return 0, io.EOF
		}
	case <-s.closed:
		return 0, io.EOF
	}
}

// consumeData copies data into p and saves the overflow for the next Read.
// Optimisation: the overflow tail is kept as a sub-slice of data (zero-copy)
// since each data slice is a fresh allocation from readLoop and is not reused.
func (s *Stream) consumeData(p, data []byte) int {
	n := copy(p, data)
	if n < len(data) {
		s.readBuf = data[n:]
	}
	return n
}

// Close sends a FIN frame to the remote and marks the stream closed locally.
// Safe to call multiple times.
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.mux.writeFrame(s.id, FrameFIN, nil) //nolint:errcheck
		s.mux.streamsMu.Lock()
		delete(s.mux.streams, s.id)
		s.mux.streamsMu.Unlock()
	})
	return nil
}

// closeLocal closes the stream without sending a FIN frame. Used by Mux.Close
// to tear down all streams when the underlying connection goes away.
func (s *Stream) closeLocal() {
	s.closeOnce.Do(func() {
		close(s.closed)
	})
}
