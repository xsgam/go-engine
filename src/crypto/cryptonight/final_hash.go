package cryptonight

import (
	"hash"
	"sync"
	"unsafe"

	"github.com/xsgam/go-engine/src/crypto/cryptonight/inter/blake256"
	"github.com/xsgam/go-engine/src/crypto/cryptonight/inter/groestl"
	"github.com/xsgam/go-engine/src/crypto/cryptonight/inter/jh"
	"github.com/xsgam/go-engine/src/crypto/cryptonight/inter/skein"
)

var hashPool = [...]*sync.Pool{
	{New: func() interface{} { return blake256.New() }},
	{New: func() interface{} { return groestl.New256() }},
	{New: func() interface{} { return jh.New256() }},
	{New: func() interface{} { return skein.New256(nil) }},
}

func (cc *CryptoNight) finalHash() []byte {
	hp := hashPool[cc.finalState[0]&0x03]
	h := hp.Get().(hash.Hash)
	h.Reset()
	h.Write((*[200]byte)(unsafe.Pointer(&cc.finalState))[:])
	sum := h.Sum(nil)
	hp.Put(h)

	return sum
}
