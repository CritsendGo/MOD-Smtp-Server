package smtp

import (
	"bytes"
)

// CramMd5 The LOGIN mechanism name.
const CramMd5 = "CRAM-MD5"

type cramMd5Client struct {
	Username string
	Password string
}

func (a *cramMd5Client) Start() (mechanic string, ir []byte, err error) {
	mechanic = "CRAM-MD5"
	ir = []byte(a.Username)
	return
}

func (a *cramMd5Client) Next(challenge []byte) (response []byte, err error) {
	if bytes.Compare(challenge, expectedChallenge) != 0 {
		return nil, ErrUnexpectedServerChallenge
	} else {
		return []byte(a.Password), nil
	}
}

func NewCramMd5Client(username, password string) SaslClient {
	return &loginClient{username, password}
}

// CramMd5Authenticator Authenticates users with an username and a password.
type CramMd5Authenticator func(username, password string) error

type crammd5State int

const (
	cramMd5NotStarted loginState = iota
	cramMd5WaitingChain
)

type cramMd5Server struct {
	state              loginState
	username, password string
	key                string
	chain              string
	authenticate       CramMd5Authenticator
}

// A server implementation of the LOGIN authentication mechanism, as described
// in https://tools.ietf.org/html/draft-murchison-sasl-login-00.
//
// LOGIN is obsolete and should only be enabled for legacy clients that cannot
// be updated to use PLAIN.
func NewCramMd5Server(authenticator func(username string, password string) error) SaslServer {
	return &cramMd5Server{authenticate: authenticator}
}

func (a *cramMd5Server) Next(response []byte) (challenge []byte, done bool, err error) {
	switch a.state {
	case cramMd5NotStarted:
		// Check for initial response field, as per RFC4422 section 3
		if response == nil {
			// Todo send a hash for encrypt / decrypt into a.key
			a.key = "sss"
			challenge = []byte("Username:")
			break
		}
		a.state++
		fallthrough
	case cramMd5WaitingChain:
		a.chain = string(response)
		// Todo decode chain with key to retrieve username and password
		err = a.authenticate(a.username, a.password)
		done = true
	default:
		err = ErrUnexpectedClientResponse
	}

	a.state++
	return
}
