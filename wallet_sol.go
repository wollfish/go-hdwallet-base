package hdwallet

import (
	"github.com/ethereum/go-ethereum/crypto"
)

func init() {
	coins[SOL] = newSOL
}

type sol struct {
	name   string
	symbol string
	key    *Key

	// trc token
	contract string
}

func newSOL(key *Key) Wallet {
	return &sol{
		name:   "Solana",
		symbol: "SOL",
		key:    key,
	}
}

func (c *sol) GetType() uint32 {
	return c.key.Opt.CoinType
}

func (c *sol) GetName() string {
	return c.name
}

func (c *sol) GetSymbol() string {
	return c.symbol
}

func (c *sol) GetKey() *Key {
	return c.key
}

func (c *sol) GetAddress() (string, error) {
	return crypto.PubkeyToAddress(*c.key.PublicECDSA).Hex(), nil
}
