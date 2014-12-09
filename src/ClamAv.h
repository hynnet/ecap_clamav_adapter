/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_ADAPTER_CLAMAV_WRAPPER
#define ECAP_ADAPTER_CLAMAV_WRAPPER

#include <clamav.h>
#include "Antivirus.h"

// libClamAV wrapper using Antivirus API
class Clamav: public Antivirus {
	public:
		Clamav();
		virtual ~Clamav();

		// Antivirus API
		virtual void configure(const Options &cfg);
		virtual void reconfigure(const Options &cfg);
		virtual void update();
		virtual void scan(const char *filename, User &user);
		
	protected:
		void setDebugging(const libecap::Area &flag);
		void close();
		void loadDatabase();

	private:
		struct cl_engine *engine;
		struct cl_stat dbstat;
		
};

#endif
