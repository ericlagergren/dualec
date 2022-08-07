package dualec

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"testing"
	"time"
)

type curveInfo struct {
	name   string
	c      Curve
	hashes []func() hash.Hash
}

var curves = []curveInfo{
	{"P-256", P256(), []func() hash.Hash{
		sha1.New,
		sha256.New224,
		sha512.New512_224,
		sha256.New,
		sha512.New512_256,
		sha512.New384,
		sha512.New,
	}},
	{"P-384", P384(), []func() hash.Hash{
		sha256.New224,
		sha512.New512_224,
		sha256.New,
		sha512.New512_256,
		sha512.New384,
		sha512.New,
	}},
	{"P-521", P521(), []func() hash.Hash{
		sha256.New,
		sha512.New512_256,
		sha512.New384,
		sha512.New,
	}},
}

func forEachCurve(t *testing.T, fn func(t *testing.T, c Curve, h func() hash.Hash)) {
	for _, v := range curves {
		t.Run(v.name, func(t *testing.T) {
			for _, h := range v.hashes {
				name := fmt.Sprintf("SHA-%d", h().Size()*8)
				t.Run(name, func(t *testing.T) {
					fn(t, v.c, h)
				})
			}
		})
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func TestRead(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c Curve, h func() hash.Hash) {
		N := (c.byteLen() * 3) + (c.byteLen() / 2)

		for i := 0; i < N; i++ {
			a, err := New(c, zeroReader{}, h)
			if err != nil {
				t.Fatal(err)
			}
			abuf := make([]byte, N)
			if _, err := io.ReadFull(a, abuf); err != nil {
				t.Fatal(err)
			}

			b, err := New(c, zeroReader{}, h)
			if err != nil {
				t.Fatal(err)
			}
			bbuf := make([]byte, N)
			if _, err := io.ReadFull(b, bbuf); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(abuf, bbuf) {
				t.Fatalf("expected %x, got %x", abuf, bbuf)
			}
		}
	})
}

func TestRecover(t *testing.T) {
	forEachCurve(t, func(t *testing.T, c Curve, h func() hash.Hash) {
		P := c.Generator()
		for i := 0; ; i++ {
			Q, d := Backdoor(c, P)
			want, err := NewWithPQ(c, P, Q, rand.Reader, sha256.New)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			got, err := Recover(c, P, Q, d, want, sha256.New)
			if err != nil {
				continue
			}
			t.Logf("recovered in %s (%d attempts)",
				time.Since(start), i+1)
			if err := compare(want, got); err != nil {
				t.Fatal(err)
			}
			return
		}
	})
}

func compare(a, b io.Reader) error {
	want := make([]byte, 30)
	if _, err := io.ReadFull(a, want); err != nil {
		return err
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(b, got); err != nil {
		return err
	}
	if !bytes.Equal(want, got) {
		return fmt.Errorf("mismatch: %x != %x", want, got)
	}
	return nil
}
