/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "ClamAv.h"

#include <libecap/common/name.h>
#include <libecap/common/area.h>
#include <libecap/common/options.h>
#include <cstring>
#include <string>
#include <stdexcept>

static const libecap::Name optDebug("debug");

inline void Throw(const char *message, const char *reason = "")
{
	std::string error(message);
	error += reason;
	error += "\n";
	throw std::runtime_error(error);
}

Clamav::Clamav(): engine(0)
{
}

Clamav::~Clamav()
{
	close();
}

void Clamav::scan(const char *filename, User &user)
{
	const char *virname = 0;
	const int ret = cl_scanfile(filename, &virname, 0, engine, CL_SCAN_STDOPT);

	if (ret == CL_CLEAN) {
		user.onClean();
		return;
	}

	if (ret == CL_VIRUS) {
		user.onVirus(virname);
		return;
	}

	user.onError(cl_strerror(ret));
}

void Clamav::configure(const Options &cfg)
{
	setDebugging(cfg.option(optDebug)); // call here to debug cl_init()

	// initialize once, to avoid "bytecode_init: already initialized"
	static bool initialized = false;
	if (!initialized) {
		const int ret = cl_init(CL_INIT_DEFAULT);
		if (ret != CL_SUCCESS)
			Throw("Can't initialize libclamav: ", cl_strerror(ret));
		initialized = true;
	}

	loadDatabase();	
}

void Clamav::reconfigure(const Options &cfg)
{
	// TODO: Does ClamAV support reconfiguration?
	setDebugging(cfg.option(optDebug));
}

void Clamav::setDebugging(const libecap::Area &flag)
{
	// TODO: use unstable cl_set_clcb_msg() API instead?

	bool wantDebugging = false; // no debugging by default
	if (flag) {
		if (flag.toString() == "full")
			wantDebugging = true;
		else
		if (flag.toString() == "none")
			wantDebugging = false;
		else
			Throw("invalid debug option value (expected 'none' or 'full'): ",
				flag.toString().c_str());
	}

	// XXX: ClamAV lacks API to query current debugging state
	if (wantDebugging)
		cl_debug();
	else
		; // cli_debug_flag = 0; // XXX: ClamAV lacks cl_nodebug();
}


void Clamav::update()
{
	// XXX: The relationship between dbstat and engine is not clear; do we need
	// multiple dbstats if we have multiple engines? If not, do we update once?
	if (cl_statchkdir(&dbstat) == 1) {

		// reload database
		close();
		loadDatabase();

		// recharge dbstat
		cl_statfree(&dbstat);
		cl_statinidir(cl_retdbdir(), &dbstat);
	}
}

void Clamav::loadDatabase()
{
	if (engine)
		Throw("Internal error: double engine load");

	if (!(engine = cl_engine_new()))
		Throw("Can't create new engine");

	try	{
		unsigned int sigs = 0;
		/* load all available databases from default directory */
		int ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
		if (ret != CL_SUCCESS)
			Throw("cl_load: ", cl_strerror(ret));

		//printf("Loaded %u signatures from %s\n", sigs, cl_retdbdir());

		// build engine
		if ((ret = cl_engine_compile(engine)) != CL_SUCCESS)
			Throw("Database initialization error: ", cl_strerror(ret));;
		
		memset(&dbstat, 0, sizeof(struct cl_stat));
		cl_statinidir(cl_retdbdir(), &dbstat);
	} catch ( ... ) {
		close();
		throw;
	}
}

void Clamav::close()
{
	if (engine) {
		cl_engine_free(engine);
		engine = 0;
	}
}

