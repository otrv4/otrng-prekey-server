package prekeyserver

type messageHandler interface {
	handleMessage(from string, message []byte) ([]byte, error)
	handleInnerMessage(from string, message []byte) (serializable, error)
}

type otrngMessageHandler struct {
	s *GenericServer
}

func (mh *otrngMessageHandler) handleMessage(from string, message []byte) ([]byte, error) {
	r, e := mh.handleInnerMessage(from, message)
	if e != nil {
		return nil, e
	}
	return r.serialize(), nil
}

func (mh *otrngMessageHandler) handleInnerMessage(from string, message []byte) (serializable, error) {
	result, e := parseMessage(message)
	if e != nil {
		return nil, e
	}

	if e := result.validate(from, mh.s); e != nil {
		return nil, e
	}

	r, e := result.respond(from, mh.s)
	if e != nil {
		return nil, e
	}

	return r, nil
}
