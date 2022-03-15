package hdwallet

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/wollac/iota-crypto-demo/pkg/ed25519"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/bchutil"
	"github.com/wollac/iota-crypto-demo/pkg/slip10"
)

const tronBytePrefix = byte(0x41)

// Key struct
type Key struct {
	Opt      *Options
	Extended *hdkeychain.ExtendedKey

	// for btc
	Private *btcec.PrivateKey
	Public  *btcec.PublicKey

	// for eth
	PrivateECDSA *ecdsa.PrivateKey
	PublicECDSA  *ecdsa.PublicKey

	// for sol
	PrivateEd25519 ed25519.PrivateKey
	PublicEd25519  ed25519.PublicKey
}

// NewKey creates a master key
// params: [Mnemonic], [Password], [Language], [Seed]
func NewKey(opts ...Option) (*Key, error) {
	var (
		err error
		o   = newOptions(opts...)
	)

	if len(o.Seed) <= 0 {
		o.Seed, err = NewSeed(o.Mnemonic, o.Password, o.Language)
	}

	if err != nil {
		return nil, err
	}

	extended, err := hdkeychain.NewMaster(o.Seed, o.Params)
	if err != nil {
		return nil, err
	}

	key := &Key{
		Opt:      o,
		Extended: extended,
	}

	err = key.init()
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (k *Key) init() error {
	var err error

	k.Private, err = k.Extended.ECPrivKey()
	if err != nil {
		return err
	}

	k.Public, err = k.Extended.ECPubKey()
	if err != nil {
		return err
	}

	k.PrivateECDSA = k.Private.ToECDSA()
	k.PublicECDSA = &k.PrivateECDSA.PublicKey

	ed25519Key, err := slip10.DeriveKeyFromPath(k.Opt.Seed, slip10.Ed25519(), k.Opt.GetPath())
	if err != nil {
		return err
	}

	k.PublicEd25519, k.PrivateEd25519 = slip10.Ed25519Key(ed25519Key)
	return nil
}

// GetChildKey return a key from master key
// params: [Purpose], [CoinType], [Account], [Change], [AddressIndex], [Path]
func (k *Key) GetChildKey(opts ...Option) (*Key, error) {
	var (
		err error
		o   = newOptions(opts...)
		no  = o
	)

	typ, ok := coinTypes[o.CoinType]
	if ok {
		no = newOptions(append(opts, CoinType(typ))...)
	}

	extended := k.Extended
	for _, i := range no.GetPath() {
		extended, err = extended.Child(i)
		if err != nil {
			return nil, err
		}
	}

	key := &Key{
		Opt:      o,
		Extended: extended,
	}

	err = key.init()
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GetWallet return wallet from master key
// params: [Purpose], [CoinType], [Account], [Change], [AddressIndex], [Path]
func (k *Key) GetWallet(opts ...Option) (Wallet, error) {
	key, err := k.GetChildKey(opts...)
	if err != nil {
		return nil, err
	}

	coin, ok := coins[key.Opt.CoinType]
	if !ok {
		return nil, ErrCoinTypeUnknow
	}

	return coin(key), nil
}

// PrivateHex generate private key to string by hex
func (k *Key) PrivateHex() string {
	return hex.EncodeToString(k.Private.Serialize())
}

// PrivateWIF generate private key to string by wif
func (k *Key) PrivateWIF(compress bool) (string, error) {
	wif, err := btcutil.NewWIF(k.Private, k.Opt.Params, compress)
	if err != nil {
		return "", err
	}

	return wif.String(), nil
}

// PublicHex generate public key to string by hex
func (k *Key) PublicHex(compress bool) string {
	if compress {
		return hex.EncodeToString(k.Public.SerializeCompressed())
	}

	return hex.EncodeToString(k.Public.SerializeUncompressed())
}

// PublicHash generate public key by hash160
func (k *Key) PublicHash() ([]byte, error) {
	address, err := k.Extended.Address(k.Opt.Params)
	if err != nil {
		return nil, err
	}

	return address.ScriptAddress(), nil
}

// AddressBTC generate public key to btc style address
func (k *Key) AddressBTC() (string, error) {
	address, err := k.Extended.Address(k.Opt.Params)
	if err != nil {
		return "", err
	}

	return address.EncodeAddress(), nil
}

// AddressBCH generate public key to bch style address
func (k *Key) AddressBCH() (string, error) {
	address, err := k.Extended.Address(k.Opt.Params)
	if err != nil {
		return "", err
	}

	addr, err := bchutil.NewCashAddressPubKeyHash(address.ScriptAddress(), k.Opt.Params)
	if err != nil {
		return "", err
	}

	data := addr.EncodeAddress()
	prefix := bchutil.Prefixes[k.Opt.Params.Name]
	return prefix + ":" + data, nil
}

// AddressP2WPKH generate public key to p2wpkh style address
func (k *Key) AddressP2WPKH() (string, error) {
	pubHash, err := k.PublicHash()
	if err != nil {
		return "", err
	}

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubHash, k.Opt.Params)
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

// AddressP2WPKHInP2SH generate public key to p2wpkh nested within p2sh style address
func (k *Key) AddressP2WPKHInP2SH() (string, error) {
	pubHash, err := k.PublicHash()
	if err != nil {
		return "", err
	}

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubHash, k.Opt.Params)
	if err != nil {
		return "", err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", err
	}

	addr1, err := btcutil.NewAddressScriptHash(script, k.Opt.Params)
	if err != nil {
		return "", err
	}

	return addr1.EncodeAddress(), nil
}

func (k *Key) AddressTron() (string, error) {
	address := crypto.PubkeyToAddress(*k.PublicECDSA)
	addressInBytes := make([]byte, 0)
	addressInBytes = append(addressInBytes, tronBytePrefix)
	addressInBytes = append(addressInBytes, address.Bytes()...)

	h256h0 := sha256.New()
	h256h0.Write(addressInBytes)
	h0 := h256h0.Sum(nil)

	h256h1 := sha256.New()
	h256h1.Write(h0)
	h1 := h256h1.Sum(nil)

	inputCheck := addressInBytes
	inputCheck = append(inputCheck, h1[:4]...)

	return base58.Encode(inputCheck), nil
}

// AddressSOL generate public base58 address for SOL blockchain
func (k *Key) AddressSOL() (string, error) {
	return base58.Encode(k.PublicEd25519), nil
}
