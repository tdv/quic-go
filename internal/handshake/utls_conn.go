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
	conn    *utls.UQUICConn
	helloID utls.ClientHelloID
	alpn    []string
	params  []byte
}

func newUTLSConn(tlsConf *tls.Config, helloID utls.ClientHelloID) *utlsConnWrapper {
	uConf := &utls.Config{
		ServerName:            tlsConf.ServerName,
		InsecureSkipVerify:    tlsConf.InsecureSkipVerify,
		VerifyPeerCertificate: tlsConf.VerifyPeerCertificate,
		RootCAs:               tlsConf.RootCAs,
		NextProtos:            tlsConf.NextProtos,
		MinVersion:            utls.VersionTLS13,
		MaxVersion:            utls.VersionTLS13,
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
		conn:    utls.UQUICClient(&utls.QUICConfig{TLSConfig: uConf}, utls.HelloCustom),
		helloID: helloID,
		alpn:    tlsConf.NextProtos,
	}
}

func (w *utlsConnWrapper) SetTransportParameters(p []byte) {
	w.params = append([]byte(nil), p...)
	w.conn.SetTransportParameters(p)
}

func (w *utlsConnWrapper) Start(ctx context.Context) error {
	spec, err := quicClientHelloSpec(w.helloID, w.alpn, w.params)
	if err != nil {
		return err
	}
	if err := w.conn.ApplyPreset(&spec); err != nil {
		return err
	}
	return w.conn.Start(ctx)
}

const extensionQUICTransportParameters = 57

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a
}

// quicClientHelloSpec adapts a browser's TCP TLS fingerprint to QUIC: TLS 1.3
// only, the connection's ALPN (also used for ALPS), the QUIC transport
// parameters extension, and without TLS-over-TCP-only extensions.
func quicClientHelloSpec(id utls.ClientHelloID, alpn []string, params []byte) (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return spec, err
	}
	spec.TLSVersMin, spec.TLSVersMax = utls.VersionTLS13, utls.VersionTLS13
	suites := spec.CipherSuites[:0]
	for _, cs := range spec.CipherSuites {
		if isGREASE(cs) || (cs >= tls.TLS_AES_128_GCM_SHA256 && cs <= tls.TLS_CHACHA20_POLY1305_SHA256) {
			suites = append(suites, cs)
		}
	}
	spec.CipherSuites = suites
	exts := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ExtendedMasterSecretExtension, *utls.RenegotiationInfoExtension, *utls.SupportedPointsExtension,
			*utls.SessionTicketExtension, *utls.StatusRequestExtension, *utls.SCTExtension, *utls.UtlsPaddingExtension,
			*utls.UtlsPreSharedKeyExtension, *utls.FakePreSharedKeyExtension:
			continue
		case *utls.ALPNExtension:
			e.AlpnProtocols = alpn
		case *utls.ApplicationSettingsExtension:
			e.SupportedProtocols = alpn
		case *utls.ApplicationSettingsExtensionNew:
			e.SupportedProtocols = alpn
		case *utls.SupportedVersionsExtension:
			versions := []uint16{}
			for _, v := range e.Versions {
				if isGREASE(v) || v == utls.VersionTLS13 {
					versions = append(versions, v)
				}
			}
			e.Versions = versions
		}
		exts = append(exts, ext)
	}
	spec.Extensions = append(exts, &utls.GenericExtension{Id: extensionQUICTransportParameters, Data: params})
	return spec, nil
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
