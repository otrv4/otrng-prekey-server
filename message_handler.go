package prekeyserver

type messageHandler interface {
	handleMessage(from string, message []byte) ([]byte, error)
}

type otrngMessageHandler struct {
	s *GenericServer
}

func (mh *otrngMessageHandler) handleMessage(from string, message []byte) ([]byte, error) {
	// TODO: implement
	parseMessage(message)
	return nil, nil
}
