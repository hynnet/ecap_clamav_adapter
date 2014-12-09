/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Service.h"
#include <libecap/common/registry.h>

// create the adapter and register with libecap to reach the host application
static
bool Register(const std::string &mode) {
	libecap::RegisterService(new Adapter::Service(mode));
	return true;
}

static const bool RegisteredReqmod = Register("REQMOD");
static const bool RegisteredRespmod = Register("RESPMOD");
