package noise

import (
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
)

type Device struct {
	privateKey    NoisePrivateKey
	publicKey     NoisePublicKey
	groupPassword string

	sessions struct {
		sync.RWMutex
		remotes map[NoisePublicKey]*Session
	}
}

func (d *Device) getRemote(pk NoisePublicKey) *Session {
	d.sessions.Lock()
	defer d.sessions.Unlock()
	s, ok := d.sessions.remotes[pk]
	if !ok {
		shk, err := d.privateKey.sharedSecret(pk)
		if err != nil {
			panic(err)
		}
		s = &Session{
			device:       d,
			remoteStatic: pk,
			sharedStatic: shk,
			presharedKey: blake2s.Sum256([]byte(d.groupPassword)),
		}
		d.sessions.remotes[pk] = s
	}
	return s
}

const HandshakeInitationRate = time.Second / 50
