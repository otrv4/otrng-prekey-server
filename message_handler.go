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
		r2, e2 := d1.respond(from, mh.s)
		if e2 != nil {
			// TODO: test
			return nil, e2
		}
		return r2.serialize(), nil
	}

	if d3, ok := result.(*dake3Message); ok {
		// TODO: d3.validate()
		r3, e3 := d3.respond(from, mh.s)
		if e3 != nil {
			// TODO: test
			return nil, e3
		}
		return r3.serialize(), nil
	}

	if rq, ok := result.(*ensembleRetrievalQueryMessage); ok {
		// TODO: rq.validate()
		r4, e4 := rq.respond(from, mh.s)
		if e4 != nil {
			// TODO: test
			return nil, e4
		}
		return r4.serialize(), nil
	}

	return nil, nil
}
