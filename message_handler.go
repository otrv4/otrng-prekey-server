package prekeyserver

type messageHandler interface {
	handleMessage(from string, message []byte) ([]byte, error)
}

type otrngMessageHandler struct {
	s *GenericServer
}

func (mh *otrngMessageHandler) handleMessage(from string, message []byte) ([]byte, error) {
	result, pe := parseMessage(message)
	if pe != nil {
		// TODO: test
		return nil, pe
	}

	if d1, ok := result.(*dake1Message); ok {
		if ev := d1.validate(); ev != nil {
			return nil, ev
		}

		r, e := d1.respond(from, mh.s)
		if e != nil {
			// TODO: test
			return nil, e
		}
		return r.serialize(), nil
	}

	if d3, ok := result.(*dake3Message); ok {
		if ev := d3.validate(from, mh.s); ev != nil {
			return nil, ev
		}

		r, e := d3.respond(from, mh.s)
		if e != nil {
			// TODO: test
			return nil, e
		}
		return r.serialize(), nil
	}

	if rq, ok := result.(*ensembleRetrievalQueryMessage); ok {
		// TODO: rq.validate()
		r, e := rq.respond(from, mh.s)
		if e != nil {
			// TODO: test
			return nil, e
		}
		return r.serialize(), nil
	}

	return nil, nil
}
