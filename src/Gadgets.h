/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_GADGETS_H
#define ECAP_CLAMAV_ADAPTER_GADGETS_H

#include <stdio.h>
#include <string>

// generate temporary filename from template and create file
// filename [in] - file name template
// filename [out] - generated file name
FILE* createTempFile(std::string& filename);

#endif
