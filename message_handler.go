package prekeyserver

import "errors"

type messageHandler interface {
	handleMessage(from string, message []byte) ([]byte, error)
}

type otrngMessageHandler struct {
	s *GenericServer
}

type toplevelMessage interface {
	validate(string, *GenericServer) error
	respond(string, *GenericServer) (serializable, error)
	toplevelMessageMarkerDontImplement()
}

func (mh *otrngMessageHandler) handleMessage(from string, message []byte) ([]byte, error) {
	result, e := parseMessage(message)
	if e != nil {
		return nil, e
	}

	top, ok := result.(toplevelMessage)
	if !ok {
		return nil, errors.New("invalid toplevel message")
	}

	if e := top.validate(from, mh.s); e != nil {
		return nil, e
	}

	r, e := top.respond(from, mh.s)
	if e != nil {
		return nil, e
	}

	return r.serialize(), nil
}
