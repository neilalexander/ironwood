/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package noise

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := newPrivateKey()
	require_NoError(t, err)

	sk2, err := newPrivateKey()
	require_NoError(t, err)

	pk1 := sk1.publicKey()
	pk2 := sk2.publicKey()

	ss1, err1 := sk1.sharedSecret(pk2)
	ss2, err2 := sk2.sharedSecret(pk1)

	if ss1 != ss2 || err1 != nil || err2 != nil {
		t.Fatal("Failed to compute shared secet")
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	d := &Device{
		privateKey: sk,
		publicKey:  sk.publicKey(),
	}
	d.sessions.remotes = map[NoisePublicKey]*Session{}
	return d
}

func require_NoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func require_Equal(t *testing.T, a, b []byte) {
	t.Helper()
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)
	dev1.groupPassword = ""
	dev2.groupPassword = ""

	peer1 := dev2.getRemote(dev1.publicKey)
	peer2 := dev1.getRemote(dev2.publicKey)

	t.Run("PrecomputedShared", func(t *testing.T) {
		require_Equal(
			t,
			peer1.sharedStatic[:],
			peer2.sharedStatic[:],
		)
	})

	t.Run("ExchangeInitiation", func(t *testing.T) {
		msg1, err := dev1.CreateMessageInitiation(peer2)
		require_NoError(t, err)

		packet := make([]byte, 0, 256)
		writer := bytes.NewBuffer(packet)
		err = binary.Write(writer, binary.LittleEndian, msg1)
		require_NoError(t, err)

		require_NoError(t, dev2.ConsumeMessageInitiation(peer1, msg1))
		require_Equal(t, peer1.chainKey[:], peer2.chainKey[:])
		require_Equal(t, peer1.hash[:], peer2.hash[:])
	})

	t.Run("ExchangeResponse", func(t *testing.T) {
		msg2, err := peer1.CreateMessageResponse()
		require_NoError(t, err)

		require_NoError(t, peer2.ConsumeMessageResponse(msg2))
		require_Equal(t, peer1.chainKey[:], peer2.chainKey[:])
		require_Equal(t, peer1.hash[:], peer2.hash[:])
	})

	var key1, key2 *Keypair
	t.Run("DeriveKeys", func(t *testing.T) {
		var err error
		if key1, err = peer1.BeginSymmetricSession(); err != nil {
			t.Fatal("failed to derive keypair for peer 1", err)
		}
		if key2, err = peer2.BeginSymmetricSession(); err != nil {
			t.Fatal("failed to derive keypair for peer 2", err)
		}
	})

	testMsg := []byte("test message 1")

	t.Run("TestKeypair1", func(t *testing.T) {
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		require_NoError(t, err)
		require_Equal(t, out, testMsg)
	})

	t.Run("TestKeypair2", func(t *testing.T) {
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		require_NoError(t, err)
		require_Equal(t, out, testMsg)
	})
}
