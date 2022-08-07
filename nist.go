package dualec

import (
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"

	"filippo.io/nistec"
)

type nistPoint[T any] interface {
	Bytes() []byte
	BytesX() ([]byte, error)
	ScalarMult(T, []byte) (T, error)
	Set(T) T
	SetBytes([]byte) (T, error)
	SetGenerator() T
}

var (
	_ nistPoint[*nistec.P256Point] = (*nistec.P256Point)(nil)
	_ nistPoint[*nistec.P384Point] = (*nistec.P384Point)(nil)
	_ nistPoint[*nistec.P521Point] = (*nistec.P521Point)(nil)
)

type nistCurve[T nistPoint[T]] struct {
	newPoint func() T
	size     int // bits
	name     string
	Q        T        // Q point
	N        *big.Int // curve order
}

var (
	_ Curve = (*nistCurve[*nistec.P256Point])(nil)
	_ Curve = (*nistCurve[*nistec.P384Point])(nil)
	_ Curve = (*nistCurve[*nistec.P521Point])(nil)
)

func (c *nistCurve[T]) byteLen() int {
	return (c.size + 7) / 8
}

func (c *nistCurve[T]) bitSize() int {
	return c.size
}

func (c *nistCurve[T]) order() *big.Int {
	return c.N
}

func (c *nistCurve[T]) q() *Point {
	return &Point{c.Q}
}

func (c *nistCurve[T]) Generator() *Point {
	return &Point{c.newPoint().SetGenerator()}
}

func (c *nistCurve[T]) NewPoint(point []byte) (*Point, error) {
	p, err := c.newPoint().SetBytes(point)
	if err != nil {
		return nil, err
	}
	return &Point{p}, nil
}

func (c *nistCurve[T]) ScalarMult(q *Point, scalar []byte) (*Point, error) {
	t, ok := q.v.(T)
	if !ok {
		return nil, fmt.Errorf("invalid point: %T", q.v)
	}
	p, err := c.newPoint().ScalarMult(t, scalar)
	if err != nil {
		return nil, err
	}
	return &Point{p}, nil
}

// P256 returns the NIST P-256 (secp256r1) curve.
func P256() Curve {
	return p256
}

var p256 = &nistCurve[*nistec.P256Point]{
	newPoint: nistec.NewP256Point,
	size:     256,
	name:     "P-256",
	Q:        p256Q,
	N:        elliptic.P256().Params().N,
}

// P384 returns the NIST P-384 (secp384r1) curve.
func P384() Curve {
	return p384
}

var p384 = &nistCurve[*nistec.P384Point]{
	newPoint: nistec.NewP384Point,
	size:     384,
	name:     "P-384",
	Q:        p384Q,
	N:        elliptic.P384().Params().N,
}

// P521 returns the NIST P-521 (secp521r1) curve.
func P521() Curve {
	return p521
}

var p521 = &nistCurve[*nistec.P521Point]{
	newPoint: nistec.NewP521Point,
	size:     521,
	name:     "P-521",
	Q:        p521Q,
	N:        elliptic.P521().Params().N,
}

var (
	p256Q = must(nistec.NewP256Point().SetBytes(unhex("04" +
		"c97445f45cdef9f0d3e05e1e585fc297235b82b5be8ff3efca67c59852018192" +
		"b28ef557ba31dfcbdd21ac46e2a91e3c304f44cb87058ada2cb815151e610046")))
	p384Q = must(nistec.NewP384Point().SetBytes(unhex("04" +
		"8e722de3125bddb05580164bfe20b8b432216a62926c57502ceede31c47816edd1e89769124179d0b695106428815065" +
		"023b1660dd701d0839fd45eec36f9ee7b32e13b315dc02610aa1b636e346df671f790f84c5e09b05674dbb7e45c803dd")))
	p521Q = must(nistec.NewP521Point().SetBytes(unhex("04" +
		"01b9fa3e518d683c6b65763694ac8efbaec6fab44f2276171a42726507dd08add4c3b3f4c1ebc5b1222ddba077f722943b24c3edfa0f85fe24d0c8c01591f0be6f63" +
		"01f3bdba585295d9a1110d1df1f9430ef8442c5018976ff3437ef91b81dc0b8132c8d5c39c32d0e004a3092b7d327c0e7a4d26d2c7b69b58f9066652911e457779de")))
)

func unhex(s string) []byte {
	return must(hex.DecodeString(s))
}

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}
