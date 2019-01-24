# collusion

exp.py
```go
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"io/ioutil"
	"log"
)

// Not sure why this isn't in common.go; it's the trivial inverse of Encrypt
func Decrypt(d *Decrypter, payload *Payload) (string, error) {
	shared := d.RecoverKey(payload.V)
	block, err := aes.NewCipher(shared)
	if err != nil {
		return "", err
	}
	ciph, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	message, err := ciph.Open(nil, payload.Nonce, payload.Body, nil)
	if err != nil {
		return "", err
	}
	return string(message), nil
}

const TEST = 0

func main() {
	var g *Group
	var dB *Decrypter
	var dC *Decrypter
	var payload *Payload

	if TEST != 0 {
		// Test group
		var err error
		g, err = NewGroup(rand.Reader, 1024)
		if err != nil {
			log.Fatal(err)
		}
		dB, err = g.Decrypter("Bob")
		if err != nil {
			log.Fatal(err)
		}
		dC, err = g.Decrypter("Carol")
		if err != nil {
			log.Fatal(err)
		}

		e := g.Encrypter()
		payload, err = Encrypt(e, "Alice", "flag{testflag}")
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Load the challenge
		dB = new(Decrypter)
		if err := loadFromFile("bobs-key.json", &dB); err != nil {
			log.Fatal(err)
		}
		dC = new(Decrypter)
		if err := loadFromFile("carols-key.json", &dC); err != nil {
			log.Fatal(err)
		}

		if dB.N.Cmp(dC.N) != 0 {
			log.Fatal("N doesn't match!")
		}

		payload = new(Payload)
		if err := loadFromFile("message.json", &payload); err != nil {
			log.Fatal(err)
		}
	}

	N := new(big.Int).Set(dB.N)

	aId, err := DecrypterId("Alice", N)
	if err != nil {
		log.Fatal(err)
	}

	bId, err := DecrypterId("Bob", N)
	if err != nil {
		log.Fatal(err)
	}

	cId, err := DecrypterId("Carol", N)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Alice's ID", aId)
	fmt.Println("Bob's ID", bId)
	fmt.Println("Carol's ID", cId)

	myPhi := new(big.Int)
	myPhi.Sub(bId, cId).Mul(myPhi, dB.D).Mul(myPhi, dC.D)
	myPhi.Add(myPhi, dB.D).Sub(myPhi, dC.D)
	myPhi.Abs(myPhi)

	fmt.Println("myPhi", myPhi)

	if TEST != 0 {
		fmt.Println("phi", phi(g.P, g.Q))
		fmt.Println("residue", new(big.Int).Mod(myPhi, phi(g.P, g.Q)))
	}

	xB := new(big.Int).ModInverse(dB.D, myPhi)
	if xB == nil {
		log.Fatal("Not relatively prime!")
	}

	x := new(big.Int).Sub(xB, bId)
	x.Mod(x, myPhi)

	xA := new(big.Int).Add(x, aId)
	xA.Mod(xA, myPhi)

	dA := &Decrypter {
		N: N,
		D: new(big.Int).ModInverse(xA, myPhi),
	}

	if TEST != 0 {
		fmt.Println("my dA", new(big.Int).Mod(dA.D, phi(g.P, g.Q)))
		realDA, err := g.Decrypter("Alice")
		if err != nil {
			panic(err)
		}
		fmt.Println("real dA", realDA.D)
	}

	message, err := Decrypt(dA, payload)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("message", message)
}

func loadFromFile(name string, x interface{}) error {
	raw, err := ioutil.ReadFile(name)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, x)
}
```