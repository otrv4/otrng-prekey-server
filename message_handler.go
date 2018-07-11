package prekeyserver

import "errors"

type messageHandler interface {
	handleMessage(from string, message []byte) ([]byte, error)
	handleInnerMessage(from string, message []byte) (serializable, error)
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

func (mh *otrngMessageHandler) handleInnerMessage(from string, message []byte) (serializable, error) {
	result, e := parseMessage(message)
	if e != nil {
		// TODO: test
		return nil, e
	}

	if s1, ok := result.(*storageInformationRequestMessage); ok {
		if ev := s1.validate(from, mh.s); ev != nil {
			return nil, ev
		}

		r1, e1 := s1.respond(from, mh.s)
		if e1 != nil {
			// TODO: test
			return nil, e1
		}
		return r1, nil
	}

	if s1, ok := result.(*publicationMessage); ok {
		// TODO: s1.validate(from, s)

		r, e := s1.respond(from, mh.s)
		if e != nil {
			// TODO: test
			return nil, e
		}
		return r, nil
	}

	return nil, nil

}
