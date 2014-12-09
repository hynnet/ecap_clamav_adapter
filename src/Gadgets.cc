/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Gadgets.h"
#include <libecap/common/errors.h>

#include <limits.h>
#include <cstring>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

static
void SysError(std::string message, const int errNo = 0,
	const char *locFile = 0, const int locLine = -1)
{
	if (errNo) {
		message += ": ";
		message += strerror(errNo);
	}
	throw libecap::TextException(message, locFile, locLine);
}

#define Here __FILE__, __LINE__

FILE* createTempFile(std::string &fileName) {
	char fnameBuf[PATH_MAX];
	strncpy(fnameBuf, fileName.c_str(), sizeof(fnameBuf));

	const int fd = mkstemp(fnameBuf);
	if (fd < 0) {
		const int errNo = errno; // save to avoid corrupting
		SysError("Temporary file (" + fileName + ") creation failure",
		   errNo, Here);
	}

	if (FILE *file = fdopen(fd, "wb+")) {
		fileName = fnameBuf;
		return file;
	}

	const int errNo = errno; // save to avoid corrupting
	(void)unlink(fnameBuf);

	SysError("Temporary file creation failure in fdopen()", errNo, Here);
	return 0; // unreached
}
