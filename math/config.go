package math

import (
	"errors"
	openssl2 "github.com/nucypher/goUmbral/openssl"
	"goUmbral/openssl"
)

//TODO pointer params so they can be nil
type Config struct {
	Curve  *openssl.Curve
	Params *UmbralParameters
}

func NewConfig(curve openssl.Curve, params UmbralParameters) Config {
	return Config{
		Curve:  &curve,
		Params: &params,
	}
}

func (cfg Config) setCurveByDefault() {
	cfg.Curve = openssl2.SECP256K1
}

func (cfg Config) curve() *openssl.Curve {
	if cfg.Curve == nil {
		cfg.setCurveByDefault()
	}
	return cfg.Curve
}

//TODO not sure of this one, need to be checked with pyUmbral version
func (cfg Config) params() *UmbralParameters {
	if cfg.Params.Curve == nil {
		cfg.setCurveByDefault()
		cfg.Params.Curve = cfg.Curve
	}
	return cfg.Params
}

func (cfg Config) setCurve(curve *openssl.Curve) error {
	if cfg.Curve != nil {
		return errors.New("you can only set the default curve once")
	} else {
		if curve == nil {
			curve = openssl2.SECP256K1
		}
		cfg.Curve = curve
		cfg.Params.Curve = curve
		return nil
	}
}

func SetDefaultCurve(curve *openssl.Curve) error {
	return Config{}.setCurve(curve)
}

func DefaultCurve() *openssl.Curve {
	return Config{}.curve()
}

func DefaultParams() *UmbralParameters {
	return Config{}.params()
}
