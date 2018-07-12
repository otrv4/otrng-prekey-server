package prekeyserver

import (
	"time"

	. "gopkg.in/check.v1"
)

func (s *GenericServerSuite) Test_realSession_save_willUpdateTouch(c *C) {
	se := &realSession{
		lastTouched: time.Now().Add(time.Duration(-11) * time.Minute),
	}

	now := time.Now()
	se.save(nil, nil, 0x00000000, nil)
	c.Assert(se.lastTouched.After(now), Equals, true)
}

func (s *GenericServerSuite) Test_realSession_instanceTag_willUpdateTouch(c *C) {
	se := &realSession{
		lastTouched: time.Now().Add(time.Duration(-11) * time.Minute),
	}

	now := time.Now()
	se.instanceTag()
	c.Assert(se.lastTouched.After(now), Equals, true)
}

func (s *GenericServerSuite) Test_realSession_clientProfile_willUpdateTouch(c *C) {
	se := &realSession{
		lastTouched: time.Now().Add(time.Duration(-11) * time.Minute),
	}

	now := time.Now()
	se.clientProfile()
	c.Assert(se.lastTouched.After(now), Equals, true)
}

func (s *GenericServerSuite) Test_realSession_pointI_willUpdateTouch(c *C) {
	se := &realSession{
		lastTouched: time.Now().Add(time.Duration(-11) * time.Minute),
	}

	now := time.Now()
	se.pointI()
	c.Assert(se.lastTouched.After(now), Equals, true)
}

func (s *GenericServerSuite) Test_realSession_keypairS_willUpdateTouch(c *C) {
	se := &realSession{
		lastTouched: time.Now().Add(time.Duration(-11) * time.Minute),
	}

	now := time.Now()
	se.keypairS()
	c.Assert(se.lastTouched.After(now), Equals, true)
}

func (s *GenericServerSuite) Test_realSession_macKey_willUpdateTouch(c *C) {
	se := &realSession{
		lastTouched: time.Now().Add(time.Duration(-11) * time.Minute),
		storedMac:   []byte{0x01},
	}

	now := time.Now()
	se.macKey()
	c.Assert(se.lastTouched.After(now), Equals, true)
}
