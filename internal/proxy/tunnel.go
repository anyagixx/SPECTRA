package proxy

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/anyagixx/SPECTRA/internal/camouflage"
	scrypto "github.com/anyagixx/SPECTRA/internal/crypto"
	"github.com/anyagixx/SPECTRA/internal/protocol"
)

const (
	bulkDataFrameWireSize = protocol.FrameHeaderSize + protocol.MaxFramePayloadSize
	upstreamRelayBufSize  = 64 * 1024
	maxVirtualConnBuffer  = 4 << 20 // 4 MiB — prevents OOM from slow consumers
)

// tunnelSender is the internal interface that both ClientTunnel and ServerTunnel
// satisfy, allowing VirtualConn to send data without type-switching.
type tunnelSender interface {
	writeData(connID uint16, data []byte) (int, error)
	sendClose(connID uint16)
	removeVirtConn(connID uint16)
}

// connIDAllocator manages unique connection IDs with safe wrap-around and reuse.
type connIDAllocator struct {
	mu    sync.Mutex
	next  uint16
	inUse map[uint16]bool
}

func newConnIDAllocator() *connIDAllocator {
	return &connIDAllocator{
		next:  1,
		inUse: make(map[uint16]bool),
	}
}

func (a *connIDAllocator) Allocate() (uint16, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	start := a.next
	for {
		id := a.next
		a.next++
		if a.next == 0 {
			a.next = 1
		}
		if !a.inUse[id] {
			a.inUse[id] = true
			return id, nil
		}
		if a.next == start {
			return 0, fmt.Errorf("proxy: no free connection IDs")
		}
	}
}

func (a *connIDAllocator) Release(id uint16) {
	a.mu.Lock()
	delete(a.inUse, id)
	a.mu.Unlock()
}

const (
	keepaliveInterval = 20 * time.Second
	keepaliveTimeout  = 60 * time.Second
)

const rekeyInterval = 30 * time.Minute

// ClientTunnel manages the QUIC connection from client to server and implements TunnelDialer.
type ClientTunnel struct {
	conn       quic.Connection
	psk        []byte
	keys       *scrypto.SessionKeys
	shaper     *camouflage.Shaper
	mux        *protocol.Muxer
	demux      *protocol.Demuxer
	connIDs    *connIDAllocator
	sendMu     sync.Mutex
	sendStream quic.SendStream
	lastDataAt atomic.Int64
	lastRecvAt atomic.Int64

	// Active virtual connections indexed by ConnID
	virtConns sync.Map // map[uint16]*VirtualConn

	ctx    context.Context
	cancel context.CancelFunc
}

// NewClientTunnel wraps a QUIC connection into a SPECTRA client tunnel.
func NewClientTunnel(conn quic.Connection, psk []byte, keys *scrypto.SessionKeys, shaper *camouflage.Shaper) *ClientTunnel {
	enc := scrypto.NewEncryptor(keys)
	dec := scrypto.NewDecryptor(keys)
	ctx, cancel := context.WithCancel(context.Background())

	t := &ClientTunnel{
		conn:    conn,
		psk:     psk,
		keys:    keys,
		shaper:  shaper,
		mux:     protocol.NewMuxer(enc),
		demux:   protocol.NewDemuxer(dec),
		connIDs: newConnIDAllocator(),
		ctx:     ctx,
		cancel:  cancel,
	}
	now := time.Now().UnixNano()
	t.lastDataAt.Store(now)
	t.lastRecvAt.Store(now)

	return t
}

// VirtualConn represents a multiplexed connection over the tunnel.
type VirtualConn struct {
	connID   uint16
	tunnel   tunnelSender
	readBuf  bytes.Buffer
	readMu   sync.Mutex
	readCond *sync.Cond
	closed   atomic.Bool
}

// NewVirtualConn creates a new virtual connection.
func NewVirtualConn(connID uint16, tunnel tunnelSender) *VirtualConn {
	vc := &VirtualConn{
		connID: connID,
		tunnel: tunnel,
	}
	vc.readCond = sync.NewCond(&vc.readMu)
	return vc
}

func (vc *VirtualConn) Read(b []byte) (int, error) {
	vc.readMu.Lock()
	defer vc.readMu.Unlock()

	for vc.readBuf.Len() == 0 {
		if vc.closed.Load() {
			return 0, io.EOF
		}
		vc.readCond.Wait()
	}

	return vc.readBuf.Read(b)
}

func (vc *VirtualConn) Write(b []byte) (int, error) {
	if vc.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	return vc.tunnel.writeData(vc.connID, b)
}

func (vc *VirtualConn) Close() error {
	if vc.closed.CompareAndSwap(false, true) {
		vc.readCond.Broadcast()
		vc.tunnel.sendClose(vc.connID)
		vc.tunnel.removeVirtConn(vc.connID)
	}
	return nil
}

// CloseWrite is used by the SOCKS5 proxy copy loop when the local client closes
// its write side. The tunnel protocol has no half-close frame, so treat it as a
// full virtual connection close to avoid leaking idle connections.
func (vc *VirtualConn) CloseWrite() error {
	return vc.Close()
}

// deliverData pushes data into the virtual connection's read buffer.
// If the buffer exceeds maxVirtualConnBuffer the connection is closed to prevent OOM.
func (vc *VirtualConn) deliverData(data []byte) {
	vc.readMu.Lock()
	bufLen := vc.readBuf.Len()
	if bufLen+len(data) > maxVirtualConnBuffer {
		vc.readMu.Unlock()
		log.Printf("[tunnel] VirtualConn %d buffer overflow (%d bytes), closing",
			vc.connID, bufLen+len(data))
		vc.Close()
		return
	}
	vc.readBuf.Write(data)
	vc.readMu.Unlock()
	vc.readCond.Signal()
}

// DialTunnel implements TunnelDialer — opens a new virtual connection through the tunnel.
func (ct *ClientTunnel) DialTunnel(ctx context.Context, destAddr string) (io.ReadWriteCloser, error) {
	if err := ct.ctx.Err(); err != nil {
		return nil, fmt.Errorf("proxy: tunnel closed: %w", err)
	}

	connID, err := ct.connIDs.Allocate()
	if err != nil {
		return nil, err
	}

	vc := NewVirtualConn(connID, ct)
	ct.virtConns.Store(connID, vc)

	// Send CONNECT command
	inner := &protocol.InnerPayload{
		Cmd:    protocol.CmdConnect,
		ConnID: connID,
		Data:   []byte(destAddr),
	}

	frame, err := ct.mux.EncryptAndFrame(protocol.FrameInput, inner)
	if err != nil {
		ct.virtConns.Delete(connID)
		ct.connIDs.Release(connID)
		return nil, fmt.Errorf("proxy: failed to send CONNECT: %w", err)
	}

	if err := ct.writeFrame(frame); err != nil {
		ct.virtConns.Delete(connID)
		ct.connIDs.Release(connID)
		return nil, fmt.Errorf("proxy: failed to write CONNECT frame: %w", err)
	}

	return vc, nil
}

// writeData sends a DATA frame through the tunnel.
// Frame types are chosen from the Markov chain for realistic traffic shape.
func (ct *ClientTunnel) writeData(connID uint16, data []byte) (int, error) {
	chunks := ct.shaper.FragmentDataWithTarget(data, bulkDataFrameWireSize)
	total := 0

	for _, chunk := range chunks {
		frameType := ct.shaper.NextFrameType()
		if frameType == protocol.FramePadding {
			frameType = protocol.FrameVideo
		}

		inner := &protocol.InnerPayload{
			Cmd:    protocol.CmdData,
			ConnID: connID,
			Data:   chunk,
		}

		frame, err := ct.mux.EncryptAndFrame(frameType, inner)
		if err != nil {
			return total, err
		}

		if err := ct.writeFrame(frame); err != nil {
			return total, err
		}

		total += len(chunk)
	}

	return total, nil
}

// sendClose sends a CLOSE frame for the given connection ID.
func (ct *ClientTunnel) sendClose(connID uint16) {
	inner := &protocol.InnerPayload{
		Cmd:    protocol.CmdClose,
		ConnID: connID,
	}

	frame, err := ct.mux.EncryptAndFrame(protocol.FrameInput, inner)
	if err != nil {
		log.Printf("[tunnel] failed to create CLOSE frame: %v", err)
		return
	}

	if err := ct.writeFrame(frame); err != nil {
		log.Printf("[tunnel] failed to write CLOSE frame: %v", err)
	}
}

// removeVirtConn removes a virtual connection and releases its ConnID for reuse.
func (ct *ClientTunnel) removeVirtConn(connID uint16) {
	ct.virtConns.Delete(connID)
	ct.connIDs.Release(connID)
}

// Done returns a channel that is closed when the tunnel is no longer usable
// (connection lost, receiver stopped, or Close was called).
func (ct *ClientTunnel) Done() <-chan struct{} {
	return ct.ctx.Done()
}

// RunReceiver reads incoming server frames and dispatches them to virtual connections.
func (ct *ClientTunnel) RunReceiver() {
	defer ct.cancel() // signal tunnel death to reconnect loop
	for {
		select {
		case <-ct.ctx.Done():
			return
		default:
		}

		stream, err := ct.conn.AcceptUniStream(ct.ctx)
		if err != nil {
			log.Printf("[tunnel] receiver stopped: %v", err)
			return
		}

		ct.handleIncomingStream(stream)
	}
}

func (ct *ClientTunnel) handleIncomingStream(stream quic.ReceiveStream) {
	for {
		frame, inner, err := ct.demux.ReadAndDecrypt(stream)
		if err != nil {
			if err != io.EOF {
				log.Printf("[tunnel] failed to read frame: %v", err)
			}
			return
		}

		ct.lastRecvAt.Store(time.Now().UnixNano())

		if frame.Type == protocol.FramePadding || inner == nil {
			continue
		}

		switch inner.Cmd {
		case protocol.CmdData:
			if v, ok := ct.virtConns.Load(inner.ConnID); ok {
				v.(*VirtualConn).deliverData(inner.Data)
			}
		case protocol.CmdClose:
			if v, ok := ct.virtConns.LoadAndDelete(inner.ConnID); ok {
				v.(*VirtualConn).closed.Store(true)
				v.(*VirtualConn).readCond.Broadcast()
				ct.connIDs.Release(inner.ConnID)
			}
		case protocol.CmdKeepalive:
			// Server echoed our keepalive — lastRecvAt already updated.
		case protocol.CmdRekey:
			// Server acknowledged rekey — apply new keys derived from the salt.
			if len(inner.Data) == scrypto.SaltSize {
				newKeys, err := scrypto.DeriveSessionKeysDirect(ct.psk, inner.Data)
				if err != nil {
					log.Printf("[tunnel] rekey derivation failed: %v", err)
				} else {
					ct.mux.Rekey(newKeys)
					ct.demux.Rekey(newKeys)
					ct.keys = newKeys
					log.Println("[tunnel] session keys rotated successfully")
				}
			}
		case protocol.CmdPadding:
			// Encrypted padding — discard silently.
		}
	}
}

// Close shuts down the client tunnel.
// If the tunnel is still connected, it sends CLOSE frames to all active virtual
// connections and waits briefly for them to reach the wire.
func (ct *ClientTunnel) Close() error {
	if ct.ctx.Err() == nil {
		ct.virtConns.Range(func(key, value any) bool {
			connID := key.(uint16)
			vc := value.(*VirtualConn)
			vc.closed.Store(true)
			vc.readCond.Broadcast()
			ct.sendClose(connID)
			return true
		})
	}
	ct.cancel()
	// Close the send stream (FIN) to flush buffered CLOSE frames.
	ct.sendMu.Lock()
	if ct.sendStream != nil {
		_ = ct.sendStream.Close()
	}
	ct.sendMu.Unlock()
	return ct.conn.CloseWithError(0, "client closing")
}

// StartPaddingGenerator runs in the background, sending encrypted padding
// frames during idle periods. The frames use realistic frame types from the
// Markov chain and are encrypted via the mux, making them indistinguishable
// from real data on the wire.
func (ct *ClientTunnel) StartPaddingGenerator() {
	go func() {
		for {
			select {
			case <-ct.ctx.Done():
				return
			default:
			}

			// Pick a realistic frame type from the Markov chain.
			frameType := ct.shaper.NextFrameType()
			if frameType == protocol.FramePadding {
				frameType = protocol.FrameVideo
			}

			delay := ct.shaper.SampleDelay(frameType)
			time.Sleep(delay)

			lastDataAt := time.Unix(0, ct.lastDataAt.Load())
			if time.Since(lastDataAt) < 250*time.Millisecond {
				continue
			}

			// Build an encrypted padding frame with random fill.
			targetSize := ct.shaper.SamplePacketSize(frameType)
			overhead := protocol.FrameHeaderSize + protocol.InnerPayloadHeaderSize + 16 // AEAD tag
			dataSize := targetSize - overhead
			if dataSize < 1 {
				dataSize = 1
			}

			paddingData := make([]byte, dataSize)
			crand.Read(paddingData)

			inner := &protocol.InnerPayload{
				Cmd:    protocol.CmdPadding,
				ConnID: 0,
				Data:   paddingData,
			}

			frame, err := ct.mux.EncryptAndFrame(frameType, inner)
			if err != nil {
				log.Printf("[tunnel] padding encrypt failed: %v", err)
				continue
			}

			if err := ct.writeFrameCore(frame, false); err != nil {
				log.Printf("[tunnel] padding write stopped: %v", err)
				return
			}
		}
	}()
}

// StartKeepalive runs a background goroutine that sends CmdKeepalive frames
// and closes the tunnel if no frames are received within keepaliveTimeout.
func (ct *ClientTunnel) StartKeepalive() {
	go func() {
		keepaliveTicker := time.NewTicker(keepaliveInterval)
		rekeyTicker := time.NewTicker(rekeyInterval)
		defer keepaliveTicker.Stop()
		defer rekeyTicker.Stop()

		for {
			select {
			case <-ct.ctx.Done():
				return
			case <-rekeyTicker.C:
				ct.initiateRekey()
			case <-keepaliveTicker.C:
				// Check for dead tunnel.
				lastRecv := time.Unix(0, ct.lastRecvAt.Load())
				if time.Since(lastRecv) > keepaliveTimeout {
					log.Printf("[tunnel] keepalive timeout — no data received for %v, closing", keepaliveTimeout)
					ct.cancel()
					return
				}

				// Send keepalive frame.
				inner := &protocol.InnerPayload{
					Cmd:    protocol.CmdKeepalive,
					ConnID: 0,
				}
				frame, err := ct.mux.EncryptAndFrame(protocol.FrameControl, inner)
				if err != nil {
					continue
				}
				if err := ct.writeFrameCore(frame, false); err != nil {
					log.Printf("[tunnel] keepalive send failed: %v", err)
					return
				}
			}
		}
	}()
}

// initiateRekey generates a fresh salt, sends CmdRekey to the server, and waits
// for the server to echo it back (handled in handleIncomingStream).
func (ct *ClientTunnel) initiateRekey() {
	salt, err := scrypto.GenerateSalt()
	if err != nil {
		log.Printf("[tunnel] rekey salt generation failed: %v", err)
		return
	}

	inner := &protocol.InnerPayload{
		Cmd:    protocol.CmdRekey,
		ConnID: 0,
		Data:   salt,
	}
	frame, err := ct.mux.EncryptAndFrame(protocol.FrameControl, inner)
	if err != nil {
		log.Printf("[tunnel] rekey encrypt failed: %v", err)
		return
	}
	if err := ct.writeFrameCore(frame, false); err != nil {
		log.Printf("[tunnel] rekey send failed: %v", err)
	}
}

// writeFrameCore is the low-level frame writer. When updateLastData is true it
// records the current time so the padding generator knows real traffic is active.
func (ct *ClientTunnel) writeFrameCore(frame *protocol.Frame, updateLastData bool) error {
	ct.sendMu.Lock()
	defer ct.sendMu.Unlock()

	if ct.sendStream == nil {
		stream, err := ct.conn.OpenUniStreamSync(ct.ctx)
		if err != nil {
			return fmt.Errorf("proxy: failed to open QUIC stream: %w", err)
		}
		ct.sendStream = stream
	}

	if err := protocol.WriteFrame(ct.sendStream, frame); err != nil {
		// Reset the broken stream so the next call will open a fresh one.
		ct.sendStream.CancelWrite(0)
		ct.sendStream = nil
		return fmt.Errorf("proxy: failed to write frame: %w", err)
	}
	if updateLastData {
		ct.lastDataAt.Store(time.Now().UnixNano())
	}

	return nil
}

func (ct *ClientTunnel) writeFrame(frame *protocol.Frame) error {
	return ct.writeFrameCore(frame, true)
}

// --- Server Tunnel ---

// ServerTunnel manages the server side of a SPECTRA connection.
type ServerTunnel struct {
	conn       quic.Connection
	psk        []byte
	keys       *scrypto.SessionKeys
	shaper     *camouflage.Shaper
	mux        *protocol.Muxer
	demux      *protocol.Demuxer
	sendMu     sync.Mutex
	sendStream quic.SendStream
	virtConns  sync.Map // map[uint16]*serverVirtConn

	ctx    context.Context
	cancel context.CancelFunc
}

// serverVirtConn pairs a virtual connection with its upstream TCP connection.
type serverVirtConn struct {
	vc       *VirtualConn
	upstream net.Conn
}

// NewServerTunnel wraps a QUIC connection into a SPECTRA server tunnel.
func NewServerTunnel(conn quic.Connection, psk []byte, keys *scrypto.SessionKeys, shaper *camouflage.Shaper) *ServerTunnel {
	enc := scrypto.NewEncryptor(keys)
	dec := scrypto.NewDecryptor(keys)
	ctx, cancel := context.WithCancel(context.Background())

	return &ServerTunnel{
		conn:   conn,
		psk:    psk,
		keys:   keys,
		shaper: shaper,
		mux:    protocol.NewMuxer(enc),
		demux:  protocol.NewDemuxer(dec),
		ctx:    ctx,
		cancel: cancel,
	}
}

// Serve reads incoming client frames and handles CONNECT/DATA/CLOSE commands.
func (st *ServerTunnel) Serve() {
	for {
		select {
		case <-st.ctx.Done():
			return
		default:
		}

		stream, err := st.conn.AcceptUniStream(st.ctx)
		if err != nil {
			log.Printf("[server-tunnel] accept stopped: %v", err)
			return
		}

		st.handleStream(stream)
	}
}

func (st *ServerTunnel) handleStream(stream quic.ReceiveStream) {
	for {
		frame, inner, err := st.demux.ReadAndDecrypt(stream)
		if err != nil {
			if err != io.EOF {
				log.Printf("[server-tunnel] frame read error: %v", err)
			}
			return
		}

		if frame.Type == protocol.FramePadding || inner == nil {
			continue
		}

		switch inner.Cmd {
		case protocol.CmdConnect:
			st.handleConnect(inner)
		case protocol.CmdData:
			st.handleData(inner)
		case protocol.CmdClose:
			st.handleClose(inner)
		case protocol.CmdRekey:
			st.handleRekey(inner)
		case protocol.CmdKeepalive:
			st.handleKeepalive()
		case protocol.CmdPadding:
			// Encrypted padding — discard silently.
		}
	}
}

func (st *ServerTunnel) handleKeepalive() {
	inner := &protocol.InnerPayload{
		Cmd:    protocol.CmdKeepalive,
		ConnID: 0,
	}
	frame, err := st.mux.EncryptAndFrame(protocol.FrameControl, inner)
	if err != nil {
		return
	}
	_ = st.writeFrame(frame)
}

func (st *ServerTunnel) handleRekey(inner *protocol.InnerPayload) {
	if len(inner.Data) != scrypto.SaltSize {
		log.Printf("[server-tunnel] invalid rekey salt size: %d", len(inner.Data))
		return
	}

	newKeys, err := scrypto.DeriveSessionKeysDirect(st.psk, inner.Data)
	if err != nil {
		log.Printf("[server-tunnel] rekey derivation failed: %v", err)
		return
	}

	// Echo the rekey acknowledgment BEFORE switching keys,
	// so the client knows when to switch.
	ack := &protocol.InnerPayload{
		Cmd:    protocol.CmdRekey,
		ConnID: 0,
		Data:   inner.Data,
	}
	frame, err := st.mux.EncryptAndFrame(protocol.FrameControl, ack)
	if err != nil {
		log.Printf("[server-tunnel] rekey ack encrypt failed: %v", err)
		return
	}
	if err := st.writeFrame(frame); err != nil {
		log.Printf("[server-tunnel] rekey ack write failed: %v", err)
		return
	}

	// Now apply the new keys.
	st.mux.Rekey(newKeys)
	st.demux.Rekey(newKeys)
	st.keys = newKeys
	log.Println("[server-tunnel] session keys rotated successfully")
}

func (st *ServerTunnel) handleConnect(inner *protocol.InnerPayload) {
	destAddr := string(inner.Data)
	log.Printf("[server-tunnel] CONNECT to %s (connID=%d)", destAddr, inner.ConnID)

	upstream, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
	if err != nil {
		log.Printf("[server-tunnel] upstream dial failed for %s: %v", destAddr, err)
		st.sendClose(inner.ConnID)
		return
	}

	vc := NewVirtualConn(inner.ConnID, st)
	svc := &serverVirtConn{vc: vc, upstream: upstream}
	st.virtConns.Store(inner.ConnID, svc)

	// Relay upstream → tunnel
	go st.relayUpstream(inner.ConnID, upstream)
}

func (st *ServerTunnel) relayUpstream(connID uint16, upstream net.Conn) {
	buf := make([]byte, upstreamRelayBufSize)
	for {
		n, err := upstream.Read(buf)
		if n > 0 {
			if _, writeErr := st.writeData(connID, buf[:n]); writeErr != nil {
				log.Printf("[server-tunnel] failed to relay upstream data for connID=%d: %v", connID, writeErr)
				st.sendClose(connID)
				_ = upstream.Close()
				return
			}
		}
		if err != nil {
			st.sendClose(connID)
			return
		}
	}
}

func (st *ServerTunnel) handleData(inner *protocol.InnerPayload) {
	v, ok := st.virtConns.Load(inner.ConnID)
	if !ok {
		return
	}
	svc := v.(*serverVirtConn)
	if svc.upstream != nil {
		if err := writeAll(svc.upstream, inner.Data); err != nil {
			log.Printf("[server-tunnel] failed to write upstream data for connID=%d: %v", inner.ConnID, err)
			st.sendClose(inner.ConnID)
			_ = svc.upstream.Close()
			st.handleClose(&protocol.InnerPayload{ConnID: inner.ConnID})
		}
	}
}

func (st *ServerTunnel) handleClose(inner *protocol.InnerPayload) {
	v, ok := st.virtConns.LoadAndDelete(inner.ConnID)
	if !ok {
		return
	}
	svc := v.(*serverVirtConn)
	if svc.upstream != nil {
		svc.upstream.Close()
	}
	svc.vc.closed.Store(true)
	svc.vc.readCond.Broadcast()
}

// writeData sends data back to the client through shaped frames.
// Frame types are chosen from the Markov chain for realistic traffic shape.
func (st *ServerTunnel) writeData(connID uint16, data []byte) (int, error) {
	chunks := st.shaper.FragmentDataWithTarget(data, bulkDataFrameWireSize)
	total := 0

	for _, chunk := range chunks {
		frameType := st.shaper.NextFrameType()
		if frameType == protocol.FramePadding {
			frameType = protocol.FrameVideo
		}

		inner := &protocol.InnerPayload{
			Cmd:    protocol.CmdData,
			ConnID: connID,
			Data:   chunk,
		}

		frame, err := st.mux.EncryptAndFrame(frameType, inner)
		if err != nil {
			return total, err
		}

		if err := st.writeFrame(frame); err != nil {
			return total, err
		}

		total += len(chunk)
	}

	return total, nil
}

func (st *ServerTunnel) sendClose(connID uint16) {
	inner := &protocol.InnerPayload{
		Cmd:    protocol.CmdClose,
		ConnID: connID,
	}

	frame, err := st.mux.EncryptAndFrame(protocol.FrameVideo, inner)
	if err != nil {
		return
	}

	if err := st.writeFrame(frame); err != nil {
		log.Printf("[server-tunnel] failed to write CLOSE frame: %v", err)
	}
}

// removeVirtConn removes a virtual connection from the server's active map.
func (st *ServerTunnel) removeVirtConn(connID uint16) {
	st.virtConns.Delete(connID)
}

// Close shuts down the server tunnel and all upstream connections.
// If the tunnel is still connected, it notifies the client with CLOSE frames.
func (st *ServerTunnel) Close() error {
	if st.ctx.Err() == nil {
		st.virtConns.Range(func(key, value any) bool {
			st.sendClose(key.(uint16))
			return true
		})
	}
	st.cancel()
	// Close the send stream (FIN) to flush buffered CLOSE frames.
	st.sendMu.Lock()
	if st.sendStream != nil {
		_ = st.sendStream.Close()
	}
	st.sendMu.Unlock()
	st.virtConns.Range(func(key, value any) bool {
		svc := value.(*serverVirtConn)
		if svc.upstream != nil {
			svc.upstream.Close()
		}
		svc.vc.closed.Store(true)
		svc.vc.readCond.Broadcast()
		return true
	})
	return st.conn.CloseWithError(0, "server closing")
}

func (st *ServerTunnel) writeFrame(frame *protocol.Frame) error {
	st.sendMu.Lock()
	defer st.sendMu.Unlock()

	if st.sendStream == nil {
		stream, err := st.conn.OpenUniStreamSync(st.ctx)
		if err != nil {
			return fmt.Errorf("proxy: failed to open QUIC stream: %w", err)
		}
		st.sendStream = stream
	}

	if err := protocol.WriteFrame(st.sendStream, frame); err != nil {
		// Reset the broken stream so the next call will open a fresh one.
		st.sendStream.CancelWrite(0)
		st.sendStream = nil
		return fmt.Errorf("proxy: failed to write frame: %w", err)
	}

	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
