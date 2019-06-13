package math

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"goUmbral/openssl"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"hash"
	"math"
	"strconv"
)

const (
	SALT_SIZE           = 32
	DEFAULT_SCRYPT_COST = 20
	SYMMETRIC_KEY_SIZE  = 128
	NONCE_SIZE          = 64
)

func generateRandNonce() [24]byte {

	nonce := make([]byte, NONCE_SIZE)
	_, err := rand.Read(nonce)

	if err != nil {
		panic(err)
	}

	var hNonce [24]byte
	copy(hNonce[:], nonce[:])

	return hNonce
}

/**
Derives a symmetric encryption key from a pair of password and salt.
WARNING: RFC7914 recommends that you use a 2^20 cost value for sensitive
files. It is NOT recommended to change the `_scrypt_cost` value unless
you know what you are doing.
*/
func NewDerivedKey(password []byte, salt []byte) ([]byte, error) {
	expN := int64(math.Pow(2, DEFAULT_SCRYPT_COST))

	derivedKey, err := scrypt.Key(
		password,
		salt,
		int(expN),
		8,
		1,
		SYMMETRIC_KEY_SIZE,
	)

	if err != nil {
		return nil, err
	}

	return derivedKey, nil
}

/**
Derives a symmetric encryption key from a pair of password and salt.
It uses Scrypt by default.
*/
func DeriveKeyFromPassword(password []byte, salt []byte) []byte {
	derivedKey, err := NewDerivedKey(password, salt)
	if err != nil {
		panic(err)
	}

	return derivedKey
}

/**
Wraps a key using a provided wrapping key.
Alternatively, it can derive the wrapping key from a password.
*/
//TODO look at pyUmbral keys function and nacl.secretbox python implementation,
// can nonce be null? if so, delete that from params
func WrapKey(keyToWrap []byte, wrappingKey []byte, password []byte, nonce *[24]byte) []byte {

	if wrappingKey == nil && password == nil {
		panic(errors.New("either password or wrapping_key must be passed"))
	}

	var wrappedKey []byte

	if password != nil && wrappingKey == nil {
		salt := make([]byte, SALT_SIZE)
		_, err := rand.Read(salt)
		if err != nil {
			panic(err)
		}
		wrappingKey = DeriveKeyFromPassword(password, salt)
		wrappedKey = salt
	}

	var hWrappingKey [32]byte
	copy(hWrappingKey[:], wrappingKey[:])

	secretbox.Seal(wrappedKey, keyToWrap, nonce, &hWrappingKey)

	return wrappedKey
}

/**
Unwraps a key using a provided wrapping key. Alternatively, it can derive
the wrapping key from a password.
*/
//TODO can nonce be null? if so, delete that from params
func UnwrapKey(wrappedKey []byte, wrappingKey []byte, password []byte, nonce *[24]byte) []byte {
	if password == nil && wrappingKey == nil {
		panic(errors.New("either password or wrapping_key must be passed"))
	}

	if password != nil && wrappingKey == nil {
		salt := wrappedKey[:SALT_SIZE]
		wrappedKey = wrappedKey[SALT_SIZE:]
		wrappingKey = DeriveKeyFromPassword(password, salt)
	}

	var unwrappedKey []byte

	var hWrappedKey [32]byte
	copy(hWrappedKey[:], wrappingKey[:])

	//TODO if Open doesnt accept nil nonce, generate a random one
	if nonce != nil {
		secretbox.Open(unwrappedKey, wrappedKey, nonce, &hWrappedKey)
	} else {
		secretbox.Open(unwrappedKey, wrappedKey, nil, &hWrappedKey)
	}

	return unwrappedKey
}

type UmbralPublicKey struct {
	PointKey Point
	Params   UmbralParameters
}

/**
Loads an Umbral public key from bytes.
*/
func PublicKeyFromBytes(keyBytes []byte, params *UmbralParameters) UmbralPublicKey {
	if params == nil {
		params = DefaultParams()
	}

	pointKey, err := BytesToPoint(keyBytes, params.Curve)
	if err != nil {
		panic(err)
	}

	return UmbralPublicKey{
		Params:   *params,
		PointKey: *pointKey,
	}
}

/**
Returns the size (in bytes) of an UmbralPublicKey given a curve.
If no curve is provided, it uses the default curve.
By default, it assumes compressed representation (is_compressed = True).
*/
func (uPubKey UmbralPublicKey) ExpectedBytesLength(curve *openssl.Curve, isCompressed bool) uint {

	if curve == nil {
		curve = DefaultCurve()
	}

	return PointLength(curve, isCompressed)
}

/**
Returns an Umbral public key as bytes.
*/
func (uPubKey UmbralPublicKey) ToBytes(isCompressed bool) []byte {

	umbralByteKey, err := uPubKey.PointKey.ToBytes(isCompressed)

	if err != nil {
		panic(err)
	}

	return umbralByteKey
}

func (uPubKey UmbralPublicKey) ToHex(isCompressed bool) string {
	return hex.EncodeToString(uPubKey.ToBytes(isCompressed))
}

func FromHex(hexUmbralPubKey string, isCompressed bool) UmbralPublicKey {

	decodedUmbralPubKey, err := hex.DecodeString(hexUmbralPubKey)

	if err != nil {
		panic(err)
	}

	return PublicKeyFromBytes(decodedUmbralPubKey, nil)
}

func (uPubKey UmbralPublicKey) ByteString() ([]byte, error) {
	return uPubKey.PointKey.ToBytes(true)
}

func (uPubKey UmbralPublicKey) Equals(umbralPubKey UmbralPublicKey) bool {
	if uPubKey.ByteString() == umbralPubKey.ByteString() {
		if uPubKey.Params.Equals(&umbralPubKey.Params) {
			return true
		} else {
			return false
		}
	}
	return false
}

func (uPubKey UmbralPublicKey) Hash() int {

	hash := sha256.New()
	hash.Write(uPubKey.ToBytes(true))

	convertedHash, err := strconv.Atoi(string(hash.Sum(nil)))

	if err != nil {
		panic(err)
	}

	return convertedHash
}

type UmbralPrivateKey struct {
	Params    UmbralParameters
	BnKey     ModBigNum
	PublicKey UmbralPublicKey
}

/*
Generates a private key and returns it.
*/
func GenerateUmbralPrivateKey(params *UmbralParameters) UmbralPrivateKey {
	if params == nil {
		params = DefaultParams()
	}

	bnKey, err := GenRandModBN(params.Curve)
	if err != nil {
		panic(err)
	}

	pointKey, err := NewPoint(params.G, bnKey.Curve)
	if err != nil {
		panic(err)
	}
	pubKey := UmbralPublicKey{
		PointKey: *pointKey,
		Params:   *params,
	}

	return UmbralPrivateKey{
		Params:    *params,
		BnKey:     *bnKey,
		PublicKey: pubKey,
	}
}

/*
Loads an Umbral private key from bytes.
Optionally, uses a wrapping key to unwrap an encrypted Umbral private key.
Alternatively, if a password is provided it will derive the wrapping key
from it.
*/
func PrivateKeyFromBytes(keyBytes []byte, wrappingKey *[]byte, password *[]byte, params *UmbralParameters, nonce *[24]byte) UmbralPrivateKey {
	if params == nil {
		params = DefaultParams()
	}

	if wrappingKey != nil && password != nil {
		keyBytes = UnwrapKey(keyBytes, *wrappingKey, *password, nonce)
	}

	bnKey, err := BytesToModBN(keyBytes, params.Curve)
	if err != nil {
		panic(err)
	}

	pointKey, err2 := NewPoint(params.G, params.Curve)
	if err2 != nil {
		panic(err2)
	}

	pubKey := UmbralPublicKey{
		PointKey: *pointKey,
		Params:   *params,
	}

	return UmbralPrivateKey{
		Params:    *params,
		BnKey:     *bnKey,
		PublicKey: pubKey,
	}
}

/*
Returns an UmbralPrivateKey as bytes with optional symmetric
encryption via nacl's Salsa20-Poly1305.
If a password is provided instead of a wrapping key, it will use
Scrypt for key derivation.
*/
func (uPrivKey UmbralPrivateKey) ToBytes(wrappingKey *[]byte, password *[]byte, nonce *[24]byte) []byte {

	keyBytes, err := uPrivKey.BnKey.Bytes()
	if err != nil {
		panic(err)
	}

	//TODO do this better
	if wrappingKey != nil || password != nil {
		if wrappingKey != nil {
			keyBytes = WrapKey(keyBytes, *wrappingKey, nil, nonce)
		} else {
			keyBytes = WrapKey(keyBytes, nil, *password, nonce)
		}
	}

	return keyBytes
}

func (uPrivKey UmbralPrivateKey) GetPublicKey() UmbralPublicKey {
	return uPrivKey.PublicKey
}

func (uPrivKey UmbralPrivateKey) ToCryptographyPrivKey() ecdsa.PrivateKey {
	//TODO dunno how to implement this, see PyUmbral and let your brain explode
}

/**
This type with its methods handles keying material for Umbral,
by allowing deterministic derivation of UmbralPrivateKeys based on labels.
Don't use this key material directly as a key.
*/
type UmbralKeyingMaterial struct {
	KeyingMaterial []byte
}

func NewUmbralKeyingMaterial(keyingMaterial *[]byte) UmbralKeyingMaterial {
	if keyingMaterial != nil {
		if len(*keyingMaterial) < 32 {
			panic(errors.New("UmbralKeyingMaterial must have size at least 32 bytes"))
		}
		return UmbralKeyingMaterial{
			KeyingMaterial: *keyingMaterial,
		}
	} else {
		casual := make([]byte, 64)
		_, err := rand.Read(casual)
		if err != nil {
			panic(err)
		}
		return UmbralKeyingMaterial{
			KeyingMaterial: casual,
		}
	}
}

func newHash() hash.Hash {
	hashh, err := blake2b.New(blake2b.Size, nil)
	if err != nil {
		panic(err)
	}
	return hashh
}

func (uKeyMat UmbralKeyingMaterial) DerivePrivKeyByLabel(label []byte, salt []byte, params *UmbralParameters) UmbralPrivateKey {

	if params == nil {
		params = DefaultParams()
	}

	//TODO dunno what secret is, if it is a random byte array to bring more security or something more specifical
	keyMaterial, err := hkdf.New(newHash, nil, salt, label).Read(uKeyMat.KeyingMaterial)
	if err != nil {
		panic(err)
	}

	bnKey, err := HashToModBN(keyMaterial, params)
	if err != nil {
		panic(err)
	}

	return UmbralPrivateKey{}
}

func KeyingMaterialFromBytes(keyBytes []byte, wrappingKey []byte, password []byte, nonce *[24]byte) UmbralKeyingMaterial {
	if wrappingKey != nil && password != nil {
		keyBytes = UnwrapKey(keyBytes, wrappingKey, password, nonce)
	}
	return UmbralKeyingMaterial{KeyingMaterial: keyBytes}
}

func (uKeyMat UmbralKeyingMaterial) ToBytes(wrappingKey []byte, password []byte, nonce *[24]byte) []byte {

	keyBytes := uKeyMat.KeyingMaterial

	if wrappingKey != nil && password != nil {
		keyBytes = WrapKey(keyBytes, wrappingKey, password, nonce)
	}

	return keyBytes
}
