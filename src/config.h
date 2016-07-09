/* 
 * Copyright © 2015 Andreas Misje
 *
 * This file is part of dhcpoptinj.
 *
 * dhcpoptinj is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.  
 *
 * dhcpoptinj is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with dhcpoptinj. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DHCPOPTINJ_CONFIG_H
#define DHCPOPTINJ_CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct Config
{
	/* Do not daemonise */
	bool foreground;
	/* Print a lot of extra information */
	bool debug;
	/* Absolute path to PID file, or NULL if writing PID is diabled */
	char *pidFile;
	/* netfilter queue number */
	uint16_t queue;
	/* DHCP options to be injected in a serialised format */
	uint8_t *dhcpOpts;
	/* Size of serialised data */
	size_t dhcpOptsSize;
	/* List of DHCP option codes to be injected */
	uint8_t *dhcpOptCodes;
	/* Size of DHCP option code array */
	size_t dhcpOptCodeCount;
	/* (none):              Whine and drop packet
	 * ignore:              Ignore existing options and add new options
	 * remove:              Remove all exisiting options and add new options
	 */
	bool ignoreExistOpt;
	bool removeExistOpt;
	/* If option injection should fail, forward/accept packet instead of dropping it
	 * */
	bool fwdOnFail;
};

struct Config *conf_parseOpts(int argc, char **argv);
void conf_destroy(struct Config *config);

#endif // DHCPOPTINJ_CONFIG_H
