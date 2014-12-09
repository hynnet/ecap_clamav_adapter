/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_ANTIVIRUS_H
#define ECAP_CLAMAV_ADAPTER_ANTIVIRUS_H

#include <libecap/common/forward.h>

class Antivirus {
	public:
		class User {
			public:
				virtual ~User() {}

				virtual void onClean() = 0;
				virtual void onVirus(const char *virusName) = 0;
				virtual void onError(const char *error) = 0;
		};

		typedef libecap::Options Options;

	public:
		virtual ~Antivirus() {}

		virtual void configure(const Options &cfg) = 0;
		virtual void reconfigure(const Options &cfg) = 0;

		virtual void scan(const char *filename, User &user) = 0;

		// refresh virus database, for example; does not change configuration
		virtual void update() = 0;
};

#endif
