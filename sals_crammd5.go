package smtp

import (
	"bytes"
)

// The LOGIN mechanism name.
const Crammd5 = "CRAMMD5"

type crmamd5Client struct {
	Username string
	Password string
}

func (a *crmamd5Client) Start() (mech string, ir []byte, err error) {
	mech = "LOGIN"
	ir = []byte(a.Username)
	return
}

func (a *crmamd5Client) Next(challenge []byte) (response []byte, err error) {
	if bytes.Compare(challenge, expectedChallenge) != 0 {
		return nil, ErrUnexpectedServerChallenge
	} else {
		return []byte(a.Password), nil
	}
}

// A client implementation of the LOGIN authentication mechanism for SMTP,
// as described in http://www.iana.org/go/draft-murchison-sasl-login
//
// It is considered obsolete, and should not be used when other mechanisms are
// available. For plaintext password authentication use PLAIN mechanism.
func NewCramMd5Client(username, password string) SaslClient {
	return &loginClient{username, password}
}

// Authenticates users with an username and a password.
type CramMd5Authenticator func(username, password string) error

type crammd5State int

const (
	crammd5NotStarted loginState = iota
	crammd5WaitingUsername
	crammd5WaitingPassword
)

type crmamd5Server struct {
	state              loginState
	username, password string
	authenticate       LoginAuthenticator
}

// A server implementation of the LOGIN authentication mechanism, as described
// in https://tools.ietf.org/html/draft-murchison-sasl-login-00.
//
// LOGIN is obsolete and should only be enabled for legacy clients that cannot
// be updated to use PLAIN.
func NewCrammd5Server(authenticator func(username string, password string) error) SaslServer {
	return &crmamd5Server{authenticate: authenticator}
}

func (a *crmamd5Server) Next(response []byte) (challenge []byte, done bool, err error) {
	switch a.state {
	case crammd5NotStarted:
		// Check for initial response field, as per RFC4422 section 3
		if response == nil {
			challenge = []byte("Username:")
			break
		}
		a.state++
		fallthrough
	case crammd5WaitingUsername:
		a.username = string(response)
		challenge = []byte("Password:")
	case crammd5WaitingPassword:
		a.password = string(response)
		err = a.authenticate(a.username, a.password)
		done = true
	default:
		err = ErrUnexpectedClientResponse
	}

	a.state++
	return
}
