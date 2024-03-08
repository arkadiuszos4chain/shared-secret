package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/bitcoinschema/go-bitcoin/v2"
	"github.com/libsv/go-bk/bec"
	"github.com/libsv/go-bk/wif"
)

const (
	alice_xpriv = "xprv9s21ZrQH143K3GCV57vXJPrJ5NyaDW6DuYx83gy2zgyR6fTSWc2C6PZgi5sx6TL4JZo617mQ1Nx4nBhY7QaaTqiACNguhb8cSVj4Q4vViVr"
	bob_xpriv   = "xprv9s21ZrQH143K4Bsk4avtodLofXV9Y9VVtkdAno5e36ijkyZXoHFCucRkA8BdFv2k54iqquBudN25YpDNSELFbLPHVDFCXjRSRju14t8NAzf"
)

func m() {
	fmt.Printf("\n\n█████████████████████████████████████████████████████████████████████████████████████████\n")
	sha := sha256.Sum256([]byte("alice@wallet.com connection request to bob@wallet.com at " + time.Now().String()))
	connectionID := sha[:]
	fmt.Printf("\nconnectionID: %s\n\n", hex.EncodeToString(connectionID))

	a_xpriv, _ := bitcoin.GenerateHDKeyFromString(alice_xpriv)
	a_xpub, _ := a_xpriv.Neuter()
	a_child, _ := bitcoin.GetHDKeyChild(a_xpub, uint32(0))
	a_pubkey, _ := a_child.ECPubKey()
	a_intermediate, _ := a_xpriv.DeriveChildFromPath("0")
	a_privkey, _ := a_intermediate.ECPrivKey()

	fmt.Printf("alice pubkey: %s\n\n", hex.EncodeToString(a_pubkey.SerialiseCompressed()))

	b_xpriv, _ := bitcoin.GenerateHDKeyFromString(bob_xpriv)
	b_xpub, _ := b_xpriv.Neuter()
	b_child, _ := bitcoin.GetHDKeyChild(b_xpub, uint32(0))
	b_pubkey, _ := b_child.ECPubKey()
	b_intermediate, _ := b_xpriv.DeriveChildFromPath("0")
	b_privkey, _ := b_intermediate.ECPrivKey()

	fmt.Printf("bob pubkey: %s\n\n", hex.EncodeToString(b_pubkey.SerialiseCompressed()))

	S_alices := sharedSecret(a_privkey, b_pubkey)
	S_bobs := sharedSecret(b_privkey, a_pubkey)

	fmt.Printf("alice secret: %s\n", hex.EncodeToString(S_alices))
	fmt.Printf("bob secret: %s\n", hex.EncodeToString(S_bobs))
	if hex.EncodeToString(S_alices) == hex.EncodeToString(S_bobs) {
		fmt.Printf("secrets are the same")
	} else {
		fmt.Printf("secrets are different")
	}

	fmt.Printf("\n\n█████████████████████████████████████████████████████████████████████████████████████████\n")

	// calculate an Hmac of the shared secret and connectionID
	ha := Hmac(S_alices, connectionID)

	fmt.Printf("\nAlice's Hmac: %s\n\n", hex.EncodeToString(ha))

	// H is h.G where G is the generator point of the curve
	X, Y := bec.S256().ScalarBaseMult(ha)

	// alice can now calculate a public key for bob using point addition of H and B
	lX, lY := bec.S256().Add(X, Y, b_pubkey.X, b_pubkey.Y)

	// encode it as a normal pubkey commpressed mode
	lPub := bec.PublicKey{
		X:     lX,
		Y:     lY,
		Curve: bec.S256(),
	}

	paymentPubKey := lPub.SerialiseCompressed()

	fmt.Printf("paymentPubKey: %s", hex.EncodeToString(paymentPubKey))

	fmt.Printf("\n\n█████████████████████████████████████████████████████████████████████████████████████████\n")
	// Now to show how Bob can unlock we'll derive a key from the same Shared Secret, connectionID, and Bob's privkey
	hb := Hmac(S_bobs, connectionID)
	fmt.Printf("\nBob's Hmac: %s\n\n", hex.EncodeToString(hb))
	var hbap big.Int
	hbloop := hbap.SetBytes(hb)
	// add hb and b mod N
	sum := b_privkey.D.Add(b_privkey.D, hbloop)
	sumModN := sum.Mod(sum, bec.S256().N)

	// derive the pubkey and check if it's what we're expecting.
	_, bobPaymentPubKey := bec.PrivKeyFromBytes(bec.S256(), sumModN.Bytes())
	bps := bobPaymentPubKey.SerialiseCompressed()
	fmt.Println("bobPaymentPubKey: ", hex.EncodeToString(bps))
	if hex.EncodeToString(paymentPubKey) == hex.EncodeToString(bobPaymentPubKey.SerialiseCompressed()) {
		fmt.Printf("\nBob will be able unlock the utxo.")
	} else {
		fmt.Printf("\nBob will not be able unlock the utxo.")
	}

	fmt.Printf("\n\n█████████████████████████████████████████████████████████████████████████████████████████\n")
}

func Hmac(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sharedSecret(privKeyA *bec.PrivateKey, pubKeyB *bec.PublicKey) []byte {
	x, y := bec.S256().ScalarMult(pubKeyB.X, pubKeyB.Y, privKeyA.D.Bytes())
	P := bec.PublicKey{
		X:     x,
		Y:     y,
		Curve: bec.S256(),
	}
	return P.SerialiseCompressed() // to match ts-sdk we encode the pubkey as compressed format which I believe is basically just the x value prepended by a single byte which indicates if y is odd or not.
}

func sirDeggenExample() {
	now := time.Now()
	randomHash := sha256.Sum256([]byte("alice@wallet.com connection request to bob@wallet.com at " + now.String()))

	fmt.Println("Alice generates a random hash and shares it with bob along with her corresponding publicKey")
	fmt.Println("randomHash: ", hex.EncodeToString(randomHash[:]))

	// here's what alice knows
	aliceWif := "L31jqxoa4e8hU2zXDNZVgzuNJfYqgchcxdkDfzc2TL1sAKTy2tSa"
	alice, _ := wif.DecodeWIF(aliceWif)
	a := alice.PrivKey.ToECDSA()

	// see can calculate
	Ax, Ay := bec.S256().ScalarMult(a.X, a.Y, randomHash[:])
	// she shares A (point coordinates)
	Apub := bec.PublicKey{
		X:     Ax,
		Y:     Ay,
		Curve: bec.S256(),
	}
	fmt.Println("alice public key: ", hex.EncodeToString(Apub.SerialiseCompressed()), "\n")

	// here's what bob knows
	bobWif := "KzCktW7nsKWehHVTgwsaYgpy4RHq9YcGUtW2ezDMwtgjWjpjJAYy"
	bob, _ := wif.DecodeWIF(bobWif)
	b := bob.PrivKey.ToECDSA()

	// he can calculate
	Bx, By := bec.S256().ScalarMult(b.X, b.Y, randomHash[:])
	// he shares B point coordinates
	Bpub := bec.PublicKey{
		X:     Bx,
		Y:     By,
		Curve: bec.S256(),
	}

	fmt.Println("Bob is able to calculate his corresponding public key and shares that.")
	fmt.Println("bob public key: ", hex.EncodeToString(Bpub.SerialiseCompressed()), "\n")

	// alice can now calculate
	aSx, aSy := bec.S256().ScalarMult(Bx, By, a.D.Bytes())
	aliceSecret := bec.PublicKey{
		X:     aSx,
		Y:     aSy,
		Curve: bec.S256(),
	}

	// bob can now calculate
	bSx, bSy := bec.S256().ScalarMult(Ax, Ay, b.D.Bytes())
	bobSecret := bec.PublicKey{
		X:     bSx,
		Y:     bSy,
		Curve: bec.S256(),
	}

	// they should be the same
	fmt.Println("They each calculate a shared secret using their private key and the counterpart's derived public key.")
	fmt.Println("alice secret: ", hex.EncodeToString(aliceSecret.X.Bytes()))
	fmt.Println("bob secret: ", hex.EncodeToString(bobSecret.X.Bytes()), "\n")

	//sharedSecret := base32.StdEncoding.EncodeToString(aliceSecret.X.Bytes())

	// fmt.Println("Alice and Bob can now use the shared secret to generate a time based set of one time passwords (TOTP) to authenticate each other.")
	// for x := 0; x < 10; x++ {
	// 	now := time.Now()
	// 	aliceOTP, _ := totp.GenerateCode(sharedSecret, now)
	// 	bobOTP, _ := totp.GenerateCode(sharedSecret, now)
	// 	fmt.Printf("aliceOTP: %s, bobOTP: %s\n", aliceOTP, bobOTP)
	// 	time.Sleep(30 * time.Second)
	// }
}

func main() {
	m()

	//fmt.Println()
	//sirDeggenExample()
}
