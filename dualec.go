// Package dualec implements the insecure, broken Dual_EC_DRBG
// algorithm.
package dualec

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
)

// Point is a point on a NIST prime curve.
//
// It does not include the point at infinity.
type Point struct {
	v interface {
		Bytes() []byte
		BytesX() ([]byte, error)
	}
}

// BytesX returns the encoding of the x-coordinate.
func (p *Point) BytesX() ([]byte, error) {
	return p.v.BytesX()
}

// Curve is a NIST prime curve.
type Curve interface {
	// Generator returns the curve's generator point.
	Generator() *Point
	// NewPoint validates and creates a Point from its encoding.
	NewPoint([]byte) (*Point, error)
	// ScalarMult performs the Point with a scalar, returning the
	// resulting Point.
	ScalarMult(*Point, []byte) (*Point, error)

	q() *Point
	byteLen() int
	bitSize() int
	order() *big.Int
}

// Backdoor computes a backdoored Q for some fixed P.
func Backdoor(c Curve, P *Point) (Q *Point, d []byte) {
	e := make([]byte, c.byteLen())
	must(rand.Read(e))
	Q = must(c.ScalarMult(P, e))
	var z big.Int
	z.ModInverse(z.SetBytes(e), c.order())
	d = z.FillBytes(make([]byte, c.byteLen()))
	return
}

// Recover returns a Reader that will produce the same output as
// the input Reader, up until it reseeds.
func Recover(c Curve, P, Q *Point, d []byte, r io.Reader, hash func() hash.Hash) (io.Reader, error) {
	outlen := ((c.bitSize() - 13) / 8) * 8
	off := c.byteLen() - (outlen / 8)

	block1 := make([]byte, 1+c.byteLen())
	if _, err := io.ReadFull(r, block1[1+off:]); err != nil {
		return nil, err
	}
	block2 := make([]byte, outlen/8)
	if _, err := io.ReadFull(r, block2); err != nil {
		return nil, err
	}

	ch := make(chan io.Reader, 1)
	var wg sync.WaitGroup
	ctr := int32(-1)
	for i := 0; i < runtime.GOMAXPROCS(-1); i++ {
		wg.Add(+1)
		go func() {
			defer wg.Done()

			block := make([]byte, len(block1))
			copy(block, block1)
			for {
				x := atomic.AddInt32(&ctr, +1)
				if x > math.MaxUint16 {
					return
				}
				binary.BigEndian.PutUint16(block[1:], uint16(x))
				block[0] = 2

				R, err := c.NewPoint(block)
				if err != nil {
					// Bad encoding (i.e., not on the curve).
					continue
				}
				s, err := must(c.ScalarMult(R, d)).BytesX()
				if err != nil {
					// Point at infinity.
					continue
				}
				s, err = must(c.ScalarMult(P, s)).BytesX()
				if err != nil {
					// Point at infinity.
					continue
				}
				r, err := must(c.ScalarMult(Q, s)).BytesX()
				if err != nil {
					// Point at infinity.
					continue
				}
				if bytes.Equal(r[off:], block2) {
					// Compute sP because of step 14.
					s, err = must(c.ScalarMult(P, s)).BytesX()
					if err != nil {
						panic(err)
					}
					r := newWithSeed(c, P, Q, s, rand.Reader, hash)
					select {
					case ch <- r:
					default:
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	select {
	case r := <-ch:
		return r, nil
	default:
		return nil, errors.New("unable to recover RNG state")
	}
}

type rng struct {
	c         Curve
	hash      func() hash.Hash
	rand      io.Reader
	strength  int
	seedlen   int
	outlen    int
	P, Q      *Point
	s         []byte
	extra     []byte
	reseedCtr int
}

// New creates a Dual_EC_DRBG instance using the default
// parameters on a particular elliptic curve.
//
// It generates seeds using the provider Reader and hash
// function.
func New(c Curve, rand io.Reader, hash func() hash.Hash) (io.Reader, error) {
	P := c.Generator()
	Q := c.q()
	return NewWithPQ(c, P, Q, rand, hash)
}

// NewWithPQ creates a Dual_EC_DRBG instance using custom
// parameters.
//
// It generates seeds using the provider Reader and hash
// function.
func NewWithPQ(c Curve, P, Q *Point, rand io.Reader, hash func() hash.Hash) (io.Reader, error) {
	seedm := make([]byte, strength(hash)/8)
	if _, err := io.ReadFull(rand, seedm); err != nil {
		return nil, err
	}
	// TODO: nonce
	return newWithSeed(c, P, Q, hashdf(hash, seedm, c.bitSize()), rand, hash), nil
}

func newWithSeed(c Curve, P, Q *Point, s []byte, rand io.Reader, hash func() hash.Hash) io.Reader {
	return &rng{
		c:       c,
		hash:    hash,
		rand:    rand,
		seedlen: c.bitSize(),
		// h=1
		outlen:   ((c.bitSize() - 13) / 8) * 8,
		strength: strength(hash),
		P:        P,
		Q:        Q,
		s:        s,
	}
}

func strength(hash func() hash.Hash) int {
	// See SP 800-57.
	return (hash().Size() * 8) / 2
}

func (g *rng) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	const (
		interval = math.MaxUint32
	)
	if len(p)/g.outlen >= interval {
		return 0, fmt.Errorf("request too large: %d", len(p))
	}

	off := g.c.byteLen() - (g.outlen / 8)

	for n < len(p) {
		if g.reseedCtr+ceil((len(p)-n)*8, g.outlen) > interval {
			if err := g.reseed(); err != nil {
				return 0, err
			}
		}

		g.s, err = must(g.c.ScalarMult(g.P, g.s)).BytesX()
		if err != nil {
			return 0, err
		}
		r, err := must(g.c.ScalarMult(g.Q, g.s)).BytesX()
		if err != nil {
			return 0, err
		}
		n += copy(p[n:], r[off:])

		g.reseedCtr++
	}

	g.s, err = must(g.c.ScalarMult(g.P, g.s)).BytesX()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ceil returns ceil(x/y).
func ceil(x, y int) int {
	return (x + y - 1) / y
}

func (g *rng) reseed() error {
	var seedm []byte
	seedm = append(seedm, g.s...)
	entropy := make([]byte, g.strength/8)
	if _, err := io.ReadFull(g.rand, entropy); err != nil {
		return err
	}
	seedm = append(seedm, entropy...)
	g.s = hashdf(g.hash, seedm, g.seedlen)
	g.reseedCtr = 0
	return nil
}

func hashdf(hash func() hash.Hash, input []byte, nbits int) []byte {
	h := hash()
	ctr := byte(1)
	var temp []byte
	for len(temp) < nbits*8 {
		h.Reset()
		h.Write([]byte{ctr})
		binary.Write(h, binary.BigEndian, uint32(nbits))
		h.Write(input)
		temp = h.Sum(temp)
		ctr++
	}
	return temp[:nbits/8]
}
