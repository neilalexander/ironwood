package quic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/Arceliar/ironwood/network"
	"github.com/lucas-clemente/quic-go"
)

type msg struct {
	addr    net.Addr
	payload []byte
}

type conn struct {
	sync.RWMutex // write-locked while dialling
	quic.Connection
}

type PacketConn struct {
	*network.PacketConn
	ctx          context.Context
	cancel       context.CancelFunc
	quicListener quic.Listener
	incoming     chan *msg
	tlsConfig    *tls.Config
	quicConfig   *quic.Config
	sessions     sync.Map // string -> *conn
}

func NewPacketConn(secret ed25519.PrivateKey) (*PacketConn, error) {
	var err error
	npc, err := network.NewPacketConn(secret)
	if err != nil {
		return nil, err
	}
	pc := &PacketConn{
		PacketConn: npc,
		incoming:   make(chan *msg),
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
			Certificates: []tls.Certificate{
				generateTLSCertificate(secret),
			},
			NextProtos: []string{"ironwood"},
		},
		quicConfig: &quic.Config{
			EnableDatagrams: true,
		},
	}
	pc.ctx, pc.cancel = context.WithCancel(context.Background())
	pc.quicListener, err = quic.Listen(npc, pc.tlsConfig, pc.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic.Listen: %w", err)
	}
	go pc.listener()
	return pc, nil
}

func generateTLSCertificate(private ed25519.PrivateKey) tls.Certificate {
	public := private.Public().(ed25519.PublicKey)
	id := hex.EncodeToString(public[:])

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: id,
		},
		SerialNumber: big.NewInt(1),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		DNSNames:     []string{id},
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		ed25519.PublicKey(public[:]),
		ed25519.PrivateKey(private[:]),
	)
	if err != nil {
		panic(fmt.Errorf("x509.CreateCertificate: %w", err))
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(private[:]))
	if err != nil {
		panic(fmt.Errorf("x509.MarshalPKCS8PrivateKey: %w", err))
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(fmt.Errorf("tls.X509KeyPair: %w", err))
	}

	return tlsCert
}

func (pc *PacketConn) listener() {
	for {
		c, err := pc.quicListener.Accept(pc.ctx)
		if err != nil {
			pc.cancel()
			return
		}
		addrstr := c.RemoteAddr().String()
		conn := &conn{
			Connection: c,
		}
		pc.sessions.Store(addrstr, conn)
		go pc.reader(c.RemoteAddr(), conn)
	}
}

func (pc *PacketConn) reader(addr net.Addr, conn *conn) {
	if conn == nil {
		panic("nil connection")
	}
	for {
		payload, err := conn.ReceiveMessage()
		if err != nil {
			pc.sessions.Delete(addr.String())
			return
		}
		pc.incoming <- &msg{
			addr:    addr,
			payload: payload,
		}
	}
}

func (pc *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-pc.ctx.Done():
		return 0, nil, fmt.Errorf("closed")
	case msg := <-pc.incoming:
		if msg != nil {
			return copy(p, msg.payload), msg.addr, nil
		}
	}
	return 0, nil, fmt.Errorf("closed")
}

func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-pc.ctx.Done():
		return 0, errors.New("closed")
	default:
	}
	addrstr := addr.String()
	v, loaded := pc.sessions.LoadOrStore(addrstr, &conn{})
	c := v.(*conn)
	if !loaded {
		c.Lock()
		defer c.Unlock()
		if c.Connection, err = quic.DialContext(pc.ctx, pc.PacketConn, addr, addr.String(), pc.tlsConfig, pc.quicConfig); err != nil {
			return
		}
		go pc.reader(addr, c)
	} else {
		c.RLock()
		defer c.RUnlock()
	}
	if c.Connection == nil {
		return
	}
	err = c.SendMessage(p)
	n = len(p)
	return
}
