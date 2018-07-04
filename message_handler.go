package prekeyserver

type messageHandler interface {
	handleMessage(from string, message []byte) ([]byte, error)
}

type otrngMessageHandler struct {
	s *GenericServer
}

func (mh *otrngMessageHandler) handleMessage(from string, message []byte) ([]byte, error) {
	result, e := parseMessage(message)
	if e != nil {
		// TODO: test
		return nil, e
	}

	if d1, ok := result.(*dake1Message); ok {
		// TODO: d1.validate()
		r2, e2 := d1.respond(mh.s)
		if e2 != nil {
			// TODO: test
			return nil, e2
		}
		return r2.serialize(), nil
	}

	return nil, nil
}
