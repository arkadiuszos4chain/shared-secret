package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	// alice
	fmt.Println("alice xPriv ", alice_xpriv)
	alice_hdXpriv, _ := bitcoin.GenerateHDKeyFromString(alice_xpriv)

	fmt.Println("get master XPub key for alice")
	alice_masterHdXpub, _ := alice_hdXpriv.Neuter()
	fmt.Println(alice_masterHdXpub)

	fmt.Println("craete alice \"paymail External PubKey\" - it is used to rotate PubKey in PKI endpoint in SPV Wallet")
	alice_ChildHdXPub, _ := bitcoin.GetHDKeyChild(alice_masterHdXpub, uint32(0)) // Paymail external XPUB
	fmt.Println("alice External Paymail Pubkey ", alice_ChildHdXPub)

	// when we call PKI url we get:
	// alice_ChildHdXPub.Child(nextNum)

	// bob
	fmt.Println("\nbob xPriv ", bob_xpriv)
	bob_hdXpriv, _ := bitcoin.GenerateHDKeyFromString(bob_xpriv)

	fmt.Println("get master XPub key for bob")
	bob_masterHdXpub, _ := bob_hdXpriv.Neuter()
	fmt.Println(bob_masterHdXpub)

	fmt.Println("craete bob \"paymail External PubKey\" - it is used to rotate PubKey in PKI endpoint in SPV Wallet")
	bob_ChildHdXpub, _ := bitcoin.GetHDKeyChild(bob_masterHdXpub, uint32(0)) // Paymail external XPUB
	fmt.Println("bob External Paymail Pubkey ", bob_ChildHdXpub)

	//
	aXpriv, _ := alice_hdXpriv.ECPrivKey()
	aMasterXpub, _ := alice_masterHdXpub.ECPubKey()
	aXPub, _ := alice_ChildHdXPub.ECPubKey()

	bXpriv, _ := bob_hdXpriv.ECPrivKey()
	bMasterXpub, _ := bob_masterHdXpub.ECPubKey()
	bXpub, _ := bob_ChildHdXpub.ECPubKey()

	fmt.Println()
	fmt.Println("Compare shared secrets from different PubKeys")
	// shared secrets
	// master based secrets
	fmt.Println("\nsecrets computed based on master XPub and xPriv (should be the same)")
	amX := sharedSecret(aXpriv, bMasterXpub)
	bmX := sharedSecret(bXpriv, aMasterXpub)

	fmt.Println("alice ", hex.EncodeToString(amX))
	fmt.Println("bob ", hex.EncodeToString(bmX))

	// child based secrets

	fmt.Println("\nsecrets computed based on External Pubkey and xPriv (they are not same)")
	aX := sharedSecret(aXpriv, bXpub)
	bX := sharedSecret(bXpriv, aXPub)

	fmt.Println("alice ", hex.EncodeToString(aX))
	fmt.Println("bob ", hex.EncodeToString(bX))

	// child xpub based on random hash
	fmt.Println("\n create new PubKey based on Master Pub key and random hash (known by both Alice and Bob)")
	randomHash := sha256.Sum256([]byte(time.Now().String()))

	arcxpubX, arcxpubY := bec.S256().ScalarMult(aMasterXpub.X, aMasterXpub.Y, randomHash[:])
	arhXpub := &bec.PublicKey{
		X:     arcxpubX,
		Y:     arcxpubY,
		Curve: bec.S256(),
	}

	brcxpubX, brcxpubY := bec.S256().ScalarMult(bMasterXpub.X, bMasterXpub.Y, randomHash[:])
	brhXpub := &bec.PublicKey{
		X:     brcxpubX,
		Y:     brcxpubY,
		Curve: bec.S256(),
	}

	fmt.Println("secrets computed based on new XPub and xPriv (should be the same)")
	fmt.Println("NOTICE: new xPub were computed usign 'ScalarMult()'")
	aX = sharedSecret(aXpriv, brhXpub)
	bX = sharedSecret(bXpriv, arhXpub)

	fmt.Println("alice ", hex.EncodeToString(aX))
	fmt.Println("bob ", hex.EncodeToString(bX))

	// childe by adding
	fmt.Println("\nsecrets computed based on new XPub and xPriv (ther ARE NOT the same)")
	fmt.Println("NOTICE: new xPub were computed usign 'Add()' - i.e. in the same way (simplified) as bitcoin.GetHDKeyChild() does for public keys")
	ilx, ily := bec.S256().ScalarBaseMult(randomHash[:])
	childX, childY := bec.S256().Add(ilx, ily, aMasterXpub.X, aMasterXpub.Y)
	arhXpub2 := &bec.PublicKey{
		X:     childX,
		Y:     childY,
		Curve: bec.S256(),
	}

	bchildX, bchildY := bec.S256().Add(ilx, ily, bMasterXpub.X, bMasterXpub.Y)
	brhXpub2 := &bec.PublicKey{
		X:     bchildX,
		Y:     bchildY,
		Curve: bec.S256(),
	}

	aX = sharedSecret(aXpriv, brhXpub2)
	bX = sharedSecret(bXpriv, arhXpub2)

	fmt.Println("alice ", hex.EncodeToString(aX))
	fmt.Println("bob ", hex.EncodeToString(bX))

	fmt.Println()

}

func sharedSecret(privKeyA *bec.PrivateKey, pubKeyB *bec.PublicKey) []byte {
	x, _ := bec.S256().ScalarMult(pubKeyB.X, pubKeyB.Y, privKeyA.D.Bytes())
	return x.Bytes() // we can use x or y - doesn't matter
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
