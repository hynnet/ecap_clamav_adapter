/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_XACTION_H
#define ECAP_CLAMAV_ADAPTER_XACTION_H

#include <libecap/adapter/xaction.h>
#include <libecap/host/host.h>
#include <libecap/host/xaction.h>
#include <libecap/common/memory.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>

#include "Antivirus.h"

namespace Adapter {

class Service;
using libecap::size_type;

class Xaction: public libecap::adapter::Xaction, public Antivirus::User 
{
	public:
		Xaction(libecap::shared_ptr<Service> aService, libecap::host::Xaction *aHostX);
		virtual ~Xaction();

		// meta-information for the host transaction
		virtual const libecap::Area option(const libecap::Name &name) const;
		virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;

		// lifecycle
		virtual void start();
		virtual void stop();

		// adapted body transmission control
		virtual void abDiscard();
		virtual void abMake();
		virtual void abMakeMore();
		virtual void abStopMaking();

		// adapted body content extraction and consumption
		virtual libecap::Area abContent(size_type offset, size_type size);
		virtual void abContentShift(size_type size);

		// virgin body state notification
		virtual void noteVbContentDone(bool atEnd);
		virtual void noteVbContentAvailable();

		// libecap::Callable API, via libecap::host::Xaction
		virtual bool callable() const;
		
		// AntivirusController methods
		virtual void onClean();
		virtual void onVirus(const char *virusName);
		virtual void onError(const char *error);
	
	protected:
		bool shouldExamine(); // decide whether to receive and scan the message

		void handleHuge(const char *where); // deal with over-the-limit vb size
		void handleError(const char *where);

		void adaptContent(std::string &chunk); // converts vb to ab
		void stopVb(); // stops receiving vb (if we are receiving it)
		libecap::host::Xaction *lastHostCall(); // clears hostx
		void useVirgin();  // tell host to use virgin message
		void useStored(); // tell host to use stored message
		void allowAccess(); // tell host to forward the message
		void blockAccess(); // tell host to deny user access
		void getUri();
				
		void debugAction(const std::string &action, const char *detail = 0);

		bool open(); // creates staging file
		void close(); // removes staging file
		FILE *abFileX(); // adapted body file pointer; throws if nil

	private:
		libecap::shared_ptr<const Service> service; // configuration access
		libecap::host::Xaction *hostx; // Host transaction rep
		libecap::Area uri; // Request-URI from headers, for logging

		std::string virusId; // ClamAV-reported "virus name" or empty

		FILE *vbFile; // stored virgin body
		std::string vbFileName; // temporary filename for vb storage
		Size vbOffset; // virgin body bytes seen and consumed by adapter
		Size abOffset; // adapted body bytes "consumed" by host

		typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
		OperationState receivingVb; // receiving of virgin body state
		OperationState sendingAb; // sending of adapted body state

		bool vbComplete; // got entire virgin body
};

}

#endif
