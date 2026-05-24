package handshake

import (
	"context"
	"crypto/tls"

	utls "github.com/refraction-networking/utls"
)

type quicTLSConn interface {
	SetTransportParameters([]byte)
	Start(context.Context) error
	HandleData(tls.QUICEncryptionLevel, []byte) error
	NextEvent() tls.QUICEvent
	ConnectionState() tls.ConnectionState
	StoreSession(*tls.SessionState) error
	SendSessionTicket(tls.QUICSessionTicketOptions) error
	Close() error
}

var _ quicTLSConn = (*tls.QUICConn)(nil)

type utlsConnWrapper struct {
	conn *utls.UQUICConn
}

func newUTLSConn(tlsConf *tls.Config, helloID utls.ClientHelloID) *utlsConnWrapper {
	uConf := &utls.Config{
		ServerName:            tlsConf.ServerName,
		InsecureSkipVerify:    tlsConf.InsecureSkipVerify,
		VerifyPeerCertificate: tlsConf.VerifyPeerCertificate,
		RootCAs:               tlsConf.RootCAs,
		NextProtos:            tlsConf.NextProtos,
		MinVersion:            tlsConf.MinVersion,
		MaxVersion:            tlsConf.MaxVersion,
		KeyLogWriter:          tlsConf.KeyLogWriter,
	}
	if tlsConf.VerifyConnection != nil {
		fn := tlsConf.VerifyConnection
		uConf.VerifyConnection = func(cs utls.ConnectionState) error {
			return fn(tls.ConnectionState{
				Version:                     cs.Version,
				HandshakeComplete:           cs.HandshakeComplete,
				DidResume:                   cs.DidResume,
				CipherSuite:                 cs.CipherSuite,
				NegotiatedProtocol:          cs.NegotiatedProtocol,
				NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual, //nolint:staticcheck
				ServerName:                  cs.ServerName,
				PeerCertificates:            cs.PeerCertificates,
				VerifiedChains:              cs.VerifiedChains,
				SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
				OCSPResponse:                cs.OCSPResponse,
			})
		}
	}
	return &utlsConnWrapper{
		conn: utls.UQUICClient(&utls.QUICConfig{TLSConfig: uConf}, helloID),
	}
}

func (w *utlsConnWrapper) SetTransportParameters(p []byte) {
	w.conn.SetTransportParameters(p)
}

func (w *utlsConnWrapper) Start(ctx context.Context) error {
	return w.conn.Start(ctx)
}

func (w *utlsConnWrapper) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return w.conn.HandleData(utls.QUICEncryptionLevel(level), data)
}

func (w *utlsConnWrapper) NextEvent() tls.QUICEvent {
	ev := w.conn.NextEvent()
	switch tls.QUICEventKind(ev.Kind) {
	case tls.QUICStoreSession, tls.QUICResumeSession:
		return tls.QUICEvent{Kind: tls.QUICNoEvent}
	}
	return tls.QUICEvent{
		Kind:  tls.QUICEventKind(ev.Kind),
		Level: tls.QUICEncryptionLevel(ev.Level),
		Data:  ev.Data,
		Suite: ev.Suite,
	}
}

func (w *utlsConnWrapper) ConnectionState() tls.ConnectionState {
	cs := w.conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual, //nolint:staticcheck
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
	}
}

func (w *utlsConnWrapper) StoreSession(_ *tls.SessionState) error {
	return nil
}

func (w *utlsConnWrapper) SendSessionTicket(_ tls.QUICSessionTicketOptions) error {
	return nil
}

func (w *utlsConnWrapper) Close() error {
	return w.conn.Close()
}
