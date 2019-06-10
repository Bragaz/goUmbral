package math

import (
	openssl2 "github.com/nucypher/goUmbral/openssl"
	"goUmbral/openssl"
)

type Config struct {
	Curve  *openssl.Curve
	Params UmbralParameters
}

func NewConfig(curve openssl.Curve, params UmbralParameters) (*Config, error) {

}

func setDefaultCurve() {
	openssl2.SECP256K1
}
