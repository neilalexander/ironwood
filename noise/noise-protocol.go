/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package noise

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Arceliar/ironwood/noise/tai64n"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "github.com_Arceliar_ironwood_noise"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 148                                           // size of handshake initiation message
	MessageResponseSize        = 92                                            // size of response message
	MessageCookieReplySize     = 64                                            // size of cookie reply message
	MessageTransportHeaderSize = 16                                            // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                          // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                         // size of largest handshake related message
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

type MessageInitiation struct {
	Type      uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Ephemeral NoisePublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageTransport struct {
	Type    uint32
	Counter uint64
	Content []byte
}

type MessageCookieReply struct {
	Type   uint32
	Nonce  [chacha20poly1305.NonceSizeX]byte
	Cookie [blake2s.Size128 + poly1305.TagSize]byte
}

type Session struct {
	device                    *Device
	sync.RWMutex                                       // protects the below
	state                     handshakeState           // handshake state
	hash                      [blake2s.Size]byte       // hash value
	chainKey                  [blake2s.Size]byte       // chain key
	presharedKey              NoisePresharedKey        // psk
	localEphemeral            NoisePrivateKey          // ephemeral secret key
	remoteStatic              NoisePublicKey           // long term key
	remoteEphemeral           NoisePublicKey           // ephemeral public key
	sharedStatic              [NoisePublicKeySize]byte // precomputed shared secret
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst, h *[blake2s.Size]byte, data []byte, salt []byte) {
	hash, _ := blake2s.New256(salt)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (h *Session) Clear() {
	clear(h.localEphemeral[:])
	clear(h.remoteEphemeral[:])
	clear(h.chainKey[:])
	clear(h.hash[:])
	h.state = handshakeZeroed
}

func (h *Session) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data, nil)
}

func (h *Session) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier), nil)
}

func (device *Device) CreateMessageInitiation(session *Session) (*MessageInitiation, error) {
	var err error
	session.hash = InitialHash
	session.chainKey = InitialChainKey
	session.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("newPrivateKey: %w", err)
	}

	session.mixHash(session.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: session.localEphemeral.publicKey(),
	}

	session.mixKey(msg.Ephemeral[:])
	session.mixHash(msg.Ephemeral[:])

	ss, err := session.localEphemeral.sharedSecret(session.remoteStatic)
	if err != nil {
		return nil, fmt.Errorf("session.localEphemeral.sharedSecret: %w", err)
	}

	var key [chacha20poly1305.KeySize]byte
	KDF2(
		&session.chainKey,
		&key,
		session.chainKey[:],
		ss[:],
	)
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], device.publicKey[:], session.hash[:])
	session.mixHash(msg.Static[:])

	if isZero(session.sharedStatic[:]) {
		return nil, fmt.Errorf("isZero: %w", errInvalidPublicKey)
	}

	KDF2(
		&session.chainKey,
		&key,
		session.chainKey[:],
		session.sharedStatic[:],
	)

	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], session.hash[:])

	session.mixHash(msg.Timestamp[:])
	session.state = handshakeInitiationCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(session *Session, msg *MessageInitiation) error {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationType {
		return fmt.Errorf("not message initiation type")
	}

	mixHash(&hash, &InitialHash, device.publicKey[:], nil)
	mixHash(&hash, &hash, msg.Ephemeral[:], nil)
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// decrypt static key
	var peerPK NoisePublicKey
	var key [chacha20poly1305.KeySize]byte
	ss, err := device.privateKey.sharedSecret(msg.Ephemeral)
	if err != nil {
		return fmt.Errorf("device.privateKey.sharedSecret: %w", err)
	}
	KDF2(&chainKey, &key, chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return fmt.Errorf("aead.Open: %w", err)
	}
	mixHash(&hash, &hash, msg.Static[:], nil)

	// verify identity

	var timestamp tai64n.Timestamp

	session.RLock()
	if isZero(session.sharedStatic[:]) {
		session.RUnlock()
		return fmt.Errorf("isZero: %w", errInvalidPublicKey)
	}
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		session.sharedStatic[:],
	)
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		session.RUnlock()
		return fmt.Errorf("aead.Open: %w", err)
	}
	mixHash(&hash, &hash, msg.Timestamp[:], nil)

	// protect against replay & flood
	replay := !timestamp.After(session.lastTimestamp)
	flood := time.Since(session.lastInitiationConsumption) <= HandshakeInitationRate
	session.RUnlock()
	if replay {
		return fmt.Errorf("replay")
	}
	if flood {
		return fmt.Errorf("flood")
	}

	session.Lock()
	session.hash = hash
	session.chainKey = chainKey
	session.remoteEphemeral = msg.Ephemeral
	if timestamp.After(session.lastTimestamp) {
		session.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(session.lastInitiationConsumption) {
		session.lastInitiationConsumption = now
	}
	session.state = handshakeInitiationConsumed
	session.Unlock()

	clear(hash[:])
	clear(chainKey[:])

	return nil
}

func (session *Session) CreateMessageResponse() (*MessageResponse, error) {
	session.Lock()
	defer session.Unlock()

	if session.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	var msg MessageResponse
	msg.Type = MessageResponseType

	// create ephemeral key
	var err error
	session.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = session.localEphemeral.publicKey()
	session.mixHash(msg.Ephemeral[:])
	session.mixKey(msg.Ephemeral[:])

	ss, err := session.localEphemeral.sharedSecret(session.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	session.mixKey(ss[:])
	ss, err = session.localEphemeral.sharedSecret(session.remoteStatic)
	if err != nil {
		return nil, err
	}
	session.mixKey(ss[:])

	// add preshared key
	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	KDF3(
		&session.chainKey,
		&tau,
		&key,
		session.chainKey[:],
		session.presharedKey[:],
	)

	session.mixHash(tau[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, session.hash[:])
	session.mixHash(msg.Empty[:])
	session.state = handshakeResponseCreated

	return &msg, nil
}

func (session *Session) ConsumeMessageResponse(msg *MessageResponse) error {
	if msg.Type != MessageResponseType {
		return fmt.Errorf("not message response type")
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	err := func() error {
		session.RLock()
		defer session.RUnlock()

		if session.state != handshakeInitiationCreated {
			return fmt.Errorf("state not handshake initiation created")
		}

		mixHash(&hash, &session.hash, msg.Ephemeral[:], nil)
		mixKey(&chainKey, &session.chainKey, msg.Ephemeral[:])

		ss, err := session.localEphemeral.sharedSecret(msg.Ephemeral)
		if err != nil {
			return err
		}
		mixKey(&chainKey, &chainKey, ss[:])
		clear(ss[:])

		if ss, err = session.device.privateKey.sharedSecret(msg.Ephemeral); err != nil {
			return err
		}
		mixKey(&chainKey, &chainKey, ss[:])
		clear(ss[:])

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			session.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:], nil)

		aead, _ := chacha20poly1305.New(key[:])
		if _, err = aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:]); err != nil {
			return err
		}
		mixHash(&hash, &hash, msg.Empty[:], nil)
		return nil
	}()
	if err != nil {
		return fmt.Errorf("no agreement: %w", err)
	}

	session.Lock()
	session.hash = hash
	session.chainKey = chainKey
	session.state = handshakeResponseConsumed
	session.Unlock()

	clear(hash[:])
	clear(chainKey[:])

	return nil
}

/* Derives a new keypair from the current handshake state
 *
 */
func (s *Session) BeginSymmetricSession() (*Keypair, error) {
	s.Lock()
	defer s.Unlock()

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if s.state == handshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			s.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if s.state == handshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			s.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return nil, fmt.Errorf("invalid state for keypair derivation: %v", s.state)
	}

	clear(s.chainKey[:])
	clear(s.hash[:])
	clear(s.localEphemeral[:])
	s.state = handshakeZeroed

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	clear(sendKey[:])
	clear(recvKey[:])

	keypair.created = time.Now()
	keypair.isInitiator = isInitiator

	return keypair, nil
}
