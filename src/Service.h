/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_SERVICE_H
#define ECAP_CLAMAV_ADAPTER_SERVICE_H

#include "Antivirus.h"
#include <libecap/adapter/service.h>
#include <stdint.h>


namespace Adapter {

using libecap::Options;
class Cfgtor;

class Service: public libecap::adapter::Service {
	public:
		Service(const std::string &aMode);
				
		// About
		virtual std::string uri() const; // unique across all vendors
		virtual std::string tag() const; // changes with version and config
		virtual void describe(std::ostream &os) const; // free-format info

		// Configuration
		virtual void configure(const Options &cfg);
		virtual void reconfigure(const Options &cfg);

		// Lifecycle
		virtual void start(); // expect makeXaction() calls
		virtual void stop(); // no more makeXaction() calls until start()
		virtual void retire(); // no more makeXaction() calls

		// Scope (XXX: this may be changed to look at the whole header)
		virtual bool wantsUrl(const char *url) const;

		// Work
		virtual libecap::adapter::Xaction *makeXaction(libecap::host::Xaction *hostx);
		
		friend class Cfgtor;

	public:
		/* configuration */
		const std::string mode; // REQMOD or RESPMOD (for unique service URI)
		uint64_t vbAccumulationLimit; // do not store/analyze more
		bool blockOnError; // whether to block when virus scanner fails
		libecap::shared_ptr<Antivirus> scanner; // virus scanner instance
		std::string tmpFileNameTemplate; // template for temporary file name generation

	protected:
		// configuration code shared by configure and reconfigure
		void setAll(const Options &cfg);
		// handle one configuration parameter
		void setOne(const libecap::Name &name, const libecap::Area &value);

		// configure tmpFileNameTemplate
		void setTmpDir(const std::string &prefix);

		// configure tmpFileNameTemplate
		void setOnError(const std::string &allowOrBlock);

		// configure accumulation limit
		void setAccumulationLimit(const std::string &value);

		// verify that configuration is working
		void checkStagingDir();

		// update virus db if needed
		void checkpoint();
		
	private:
		time_t lastDbUpdate; // last database update timestamp
};

}

#endif
