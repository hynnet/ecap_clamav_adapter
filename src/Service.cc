/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Service.h"
#include "Xaction.h"
#include "ClamAv.h"
#include "Debugger.h"
#include "Gadgets.h"
#include <libecap/common/errors.h>
#include <libecap/common/named_values.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <cstdio>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

static const time_t timeNone = static_cast<time_t>(-1);

// Time between clamav database update checks
// Is it better to update externally instead?
//    Yes, but would external updates affect existing engine??
// 0 = on every access; timeNone = never
const time_t dbUpdateGap = 60; // in seconds

// default staging filename template
static const std::string TmpFileNameTemplateDefault =
	"/tmp/eclamavXXXXXX"; // TODO: use $TEMP


Adapter::Service::Service(const std::string &aMode):
	mode(aMode),
	vbAccumulationLimit(0),
	blockOnError(false),
	tmpFileNameTemplate(TmpFileNameTemplateDefault),
	lastDbUpdate(0)
{
}

std::string Adapter::Service::uri() const
{
	return "ecap://e-cap.org/ecap/services/clamav?mode=" + mode;
}

std::string Adapter::Service::tag() const
{
	return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream &os) const
{
	os << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

namespace Adapter {
class Cfgtor: public libecap::NamedValueVisitor {
	public:
		Cfgtor(Service &aSvc): svc(aSvc) {}
		virtual void visit(const libecap::Name &name, const libecap::Area &value) {
			svc.setOne(name, value);
		}
		Service &svc;
};
} // namespace Adapter

void Adapter::Service::configure(const Options &cfg) {
	setAll(cfg);

	// create an antivirus scanner; TODO: should some services share instances?
	Must(!scanner);
	static int scannerCount = 0;
	++scannerCount;
	Debugger(ilNormal|flApplication) << "eClamAV: " <<
		"Initializing ClamAV engine #" << scannerCount << ".";
	scanner.reset(new Clamav);
	scanner->configure(cfg);

	checkpoint();
}

void Adapter::Service::reconfigure(const Options &newCfg)
{
	setAll(newCfg);
	Must(scanner);
	scanner->reconfigure(newCfg);
	checkpoint();
}

void Adapter::Service::setAll(const Options &cfg) {
	Cfgtor cfgtor(*this);
	cfg.visitEachOption(cfgtor);

	checkStagingDir();
}

void Adapter::Service::setOne(const libecap::Name &name, const libecap::Area &valArea) {
	const std::string value = valArea.toString();
	if (name == "on_error")
		setOnError(value);
	else
	if (name == "staging_dir")
		setTmpDir(value);
	else
	if (name == "huge_size")
		setAccumulationLimit(value);
	else
	if (name == "debug")
		; // the scanner handles that (TODO: ask the scanner instead)
	else
	if (name.assignedHostId())
		; // skip host-specific options
	else
		throw libecap::TextException("eClamAV: "
			"unsupported adapter configuration parameter: " + name.image());
}

void Adapter::Service::setOnError(const std::string &value) {
	// default is not to block
	if (value == "block")
		blockOnError = true;
	else
	if (value == "allow")
		blockOnError = false;
	else
		throw libecap::TextException("eClamAV: unsupported on_error config "
			"value (" + uri() + "): " + value);
}

void Adapter::Service::setTmpDir(const std::string &prefix) {
	std::string temp = prefix;
	if (temp.empty() || temp == "default")
		temp = TmpFileNameTemplateDefault;
	if (temp.rfind('X') != temp.size()-1)
		temp += "XXXXXX";
	tmpFileNameTemplate = temp;
}

void Adapter::Service::checkStagingDir() {
	std::string tmpFileName = tmpFileNameTemplate;
	if (FILE *file = createTempFile(tmpFileName)) {
		// we do not check problems with syscalls below because Xactions do not
		fclose(file);
		remove(tmpFileName.c_str());
	}
}

void Adapter::Service::setAccumulationLimit(const std::string &value) {
	if (value == "none") {
		vbAccumulationLimit = 0; // no limit
		return;
	}

	std::istringstream input(value);
	uint64_t size;
	if (input >> size) {
		vbAccumulationLimit = size;
		return;
	}
	const std::string msg = "invalid huge_size parameter value: " + value;
	throw libecap::TextException(msg);
}

void Adapter::Service::start()
{
	Must(tmpFileNameTemplate.size() > 0); // we were successfully configured
	libecap::adapter::Service::start();
}

void Adapter::Service::stop()
{
	libecap::adapter::Service::stop();
}

void Adapter::Service::retire()
{
	libecap::adapter::Service::retire();
}

bool Adapter::Service::wantsUrl(const char *url) const
{
	return true; // no-op is applied to all messages
}

libecap::adapter::Xaction *Adapter::Service::makeXaction(libecap::host::Xaction *hostx)
{
	checkpoint();
	return new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self), hostx);
}

void Adapter::Service::checkpoint()
{
	if (dbUpdateGap == timeNone)
		return; // no updates configured

	if (time(0) < lastDbUpdate + dbUpdateGap)
		scanner->update();

	// we enforce the time gap _between_ updates so that even relatively long
	// updates do not lead to gap-free uptates
	lastDbUpdate = time(0); 
}
