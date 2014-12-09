/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "Xaction.h"
#include "Debugger.h"
#include "Gadgets.h"
#include "Service.h"

#include <libecap/common/registry.h>
#include <libecap/common/named_values.h>
#include <libecap/common/errors.h>

#include <algorithm>
#include <sstream>
#include <limits.h>
#include <cstring>
#include <errno.h>


// when host asks for a piece of adapted body, we do not read more than this
static const libecap::size_type abBufSizeMax(16*1024);

// logged actions
static const std::string actClean = "no viruses found";
static const std::string actVirus = "virus found";
static const std::string actErrorLate = "late adapter error";
static const std::string actErrorBlock = "blocking on virus check error";
static const std::string actErrorAllow = "allowing despite virus check error";
static const std::string actErrorSalvaged = "ignoring virus check error";
static const std::string actExamine = "virus check needed";
static const std::string actSkipped = "virus check skipped";


Adapter::Xaction::Xaction(libecap::shared_ptr<Service> aService,
	libecap::host::Xaction *aHostX):
	service(aService),
	hostx(aHostX),
	vbFile(0),
	vbOffset(0),
	abOffset(0),
	receivingVb(opUndecided),
	sendingAb(opUndecided),
	vbComplete(false)
{
}

Adapter::Xaction::~Xaction()
{
	if (vbFile)
		close();

	const bool stillReceiving = receivingVb == opUndecided || receivingVb == opOn;
	const bool stillSending = sendingAb == opUndecided || sendingAb == opOn;
	if (hostx && (stillReceiving || stillSending))
		lastHostCall()->adaptationAborted();
}

const libecap::Area Adapter::Xaction::option(const libecap::Name &name) const
{
	if (name == libecap::metaVirusId && !virusId.empty())
		return libecap::Area(virusId.data(), virusId.size());

	return libecap::Area();
}

void Adapter::Xaction::visitEachOption(libecap::NamedValueVisitor &visitor) const
{
	if (!virusId.empty())
		visitor.visit(libecap::metaVirusId,
			libecap::Area(virusId.data(), virusId.size()));
}

void Adapter::Xaction::start()
{
	Must(hostx);

	getUri();	
	
	if (!shouldExamine()) {
		receivingVb = opNever;
		allowAccess();
		return;
	}

	receivingVb = opOn;
	hostx->vbMake(); // ask host to supply virgin body
}

bool Adapter::Xaction::shouldExamine() {
	if (!hostx->virgin().body()) {
		debugAction(actSkipped, "no body");
		return false;
	}

	if (!service->vbAccumulationLimit) {
		debugAction(actExamine, "no body size limit");
		return true;
	}

	const libecap::Header &header = hostx->virgin().header();

	if (!header.hasAny(libecap::headerContentLength)) {
		debugAction(actExamine, "unknown body length");
		return true;
	}

	if (header.hasAny(libecap::headerTransferEncoding)) {
		debugAction(actExamine, "chunked body");
		return true;
	}

	const libecap::Area lenVal = header.value(libecap::headerContentLength);
	const std::string buf(lenVal.start, lenVal.size);
	std::istringstream is(buf);
	uint64_t len = 0;
	if (!(is >> len)) {
		debugAction(actExamine, "malformed body length");
		return true;
	}

	Debugger(flXaction) << "eClamAv: expected body length: " << len;	

	if (len >= service->vbAccumulationLimit) {
		debugAction(actSkipped, "huge body");
		return false;
	}

	debugAction(actExamine, "acceptable body length");
	return true;
}

void Adapter::Xaction::stop()
{
	hostx = 0;
	// the caller will delete
}

void Adapter::Xaction::abDiscard()
{
	Must(sendingAb == opUndecided); // have not started yet
	sendingAb = opNever;

	// TODO: close and remove the file here instead of waiting for the dtor

	// we do not need more vb if the host is not interested in ab
	stopVb();
}

void Adapter::Xaction::abMake()
{
	Must(sendingAb == opUndecided); // have not started or decided not to send
	Must(vbFile); // we should not have promissed a body otherwise
	Must(hostx); // we should not have promissed a body otherwise
	sendingAb = opOn;
	abOffset = 0;
	hostx->noteAbContentAvailable();

    // one noteAbContentAvailable is enough because we have the entire ab

	sendingAb = opComplete;
	if (hostx)
		hostx->noteAbContentDone(vbComplete);
}

void Adapter::Xaction::abMakeMore()
{
	// we cannot really make more than we already made
	Must(false && "cannot make more ab");
}

void Adapter::Xaction::abStopMaking()
{
	Must(sendingAb == opOn || sendingAb == opComplete);
	sendingAb = opComplete;

	// TODO: close and remove the file here instead of waiting for the dtor
	
	// we do not need more vb if the host is not interested in ab
	stopVb();
}

libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size)
{
	Must(sendingAb == opOn || sendingAb == opComplete);
	Must(receivingVb == opComplete);

	if (!size)
		return libecap::Area();

	Must(vbFile);

	const size_type pos = abOffset + offset;
	Must(pos <= INT_MAX); // XXX: 64-bit problems?
	Must(fseek(vbFile, pos, SEEK_SET) == 0);

	const size_type bufSize = std::min(size, abBufSizeMax);
	char buffer[bufSize];

	if (const size_t readBytes = fread(buffer, 1, sizeof(buffer), vbFile))
		return libecap::Area::FromTempBuffer(buffer, readBytes);

	return libecap::Area();
}

void Adapter::Xaction::abContentShift(size_type bytes)
{
	Must(sendingAb == opOn || sendingAb == opComplete);
	abOffset += bytes;
	// since we use a disk file, we do not shift its contents
}

void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
	Must(receivingVb == opOn);
	stopVb();
	vbComplete = atEnd;
	
	if (!vbOffset) {
		debugAction(actSkipped, "empty body after all");
		allowAccess();
		return;
	}
	
	Must(vbFile);
	fflush(vbFile);

	libecap::shared_ptr<Antivirus> scanner = service->scanner;
	Must(scanner);
	scanner->scan(vbFileName.c_str(), *this); // will call our on*() method
}

void Adapter::Xaction::noteVbContentAvailable()
{
	Must(receivingVb == opOn);
	Must(hostx);
	
	// get all vb bytes that the host has buffered
	const libecap::Area vb = hostx->vbContent(0, libecap::nsize);
		
	if (service->vbAccumulationLimit > 0 && // enabled
		vbOffset + vb.size >= service->vbAccumulationLimit) { // reached
		handleHuge("huge body after all");
		return;
	}

	if (!vbFile && !open())
		return;

	const size_t written = fwrite(vb.start, 1, vb.size, vbFile);
	if (written != vb.size) {
		handleError(strerror(errno));
		return;
	}

	// TODO: optimize to minimize shifting so that we can useVirgin more often
	vbOffset += written;
	hostx->vbContentShift(written);
}

void Adapter::Xaction::useVirgin()
{
	Must(sendingAb == opUndecided);
	sendingAb = opNever;

	Must(!vbOffset); // cannot use vb if we consumed some of it already
	stopVb();

	lastHostCall()->useVirgin();
}

void Adapter::Xaction::useStored()
{
	// we may have no body if it was promissed to us but was not delivered
	Must(hostx);

	Must(sendingAb == opUndecided);

	libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
	Must(adapted != 0);
	hostx->useAdapted(adapted); // will probably call our abMake
}

void Adapter::Xaction::allowAccess() {
	if (!vbOffset) // we have not nibbled at the host-buffered virgin message
		useVirgin();
	else
		useStored();
}

void Adapter::Xaction::blockAccess()
{
	Must(hostx);
	hostx->blockVirgin();
}

// tells the host that we are not interested in [more] vb
// if the host does not know that already
void Adapter::Xaction::stopVb() {
	if (receivingVb == opOn) {
		Must(hostx);
		hostx->vbStopMaking();
		receivingVb = opComplete;
	} else
	if (receivingVb == opUndecided)
		receivingVb = opNever;
}

bool Adapter::Xaction::callable() const
{
	return hostx != 0; // no point to call us if we are done
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
// TODO: replace with hostx-independent "done" method
libecap::host::Xaction *Adapter::Xaction::lastHostCall()
{
	libecap::host::Xaction *x = hostx;
	Must(x);
	hostx = 0;
	return x;
}

void Adapter::Xaction::debugAction(const std::string &act, const char *reason)
{
	// TODO: add and log transaction ID
	Debugger(flXaction) <<
		"eClamAv: " << act <<
		(reason ? ": " : "") << (reason ? reason : "") <<
		" (" << service->mode << ' ' << uri << ")";
}

void Adapter::Xaction::handleHuge(const char *where)
{
	debugAction(actSkipped, where);
	allowAccess(); // TODO: make allow/block decision configurable
}

void Adapter::Xaction::onClean()
{
	debugAction(actClean);
	allowAccess();
}

void Adapter::Xaction::onVirus(const char *virusName)
{
	Must(receivingVb == opComplete);
	Must(sendingAb == opUndecided);

	debugAction(actVirus, virusName);
	virusId = virusName; // copy
	blockAccess();
}

void Adapter::Xaction::onError(const char *error)
{
	Must(receivingVb == opComplete || receivingVb == opOn);
	Must(sendingAb == opUndecided);
	handleError(error);
}

void Adapter::Xaction::handleError(const char *error)
{
	// we can handle errors before/during scanning, but after we call use*(),
	// all errors must be propagated to the host via exceptions
	if (sendingAb != opUndecided) { // too late to change anything
		debugAction(actErrorLate, error);
		throw TextExceptionHere(error);
	}

	if (service->blockOnError) {
		debugAction(actErrorBlock, error);
		blockAccess();
	} else {
		debugAction(actErrorAllow, error);
		allowAccess();
	}
}

void Adapter::Xaction::getUri()
{
	if (!hostx)
		return;

	typedef const libecap::RequestLine *CLRLP;
	if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->virgin().firstLine()))
		uri = requestLine->uri();
	else
	if (CLRLP requestLine = dynamic_cast<CLRLP>(&hostx->cause().firstLine()))
		uri = requestLine->uri();
}


bool Adapter::Xaction::open() {
	try {
		Must(!vbFile);
		vbFileName = service->tmpFileNameTemplate;
		vbFile = createTempFile(vbFileName);
		return true;
	}
	catch (const std::exception &e) {
		handleError(e.what());
	}
	return false;
}


void Adapter::Xaction::close() {
	if (fclose(vbFile) != 0)
		debugAction(actErrorSalvaged, strerror(errno));
	vbFile = 0;

	if (remove(vbFileName.c_str()) != 0)
		debugAction(actErrorSalvaged, strerror(errno));
	vbFileName.clear();
}
