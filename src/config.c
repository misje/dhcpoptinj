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

#include <stdlib.h>
#include <getopt.h>
#include "config.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include "options.h"
#include <ctype.h>
#include "dhcp.h"

static const char defaultPIDFilePath[] = "/var/run/dhcpoptinj.pid";

static struct Config *createDefaultConfig();
static void printUsage(const char *programName);
static void printHelp(const char *programName);
static void printVersion(const char *programName);
static int parseQueueNum(const char *string, uint16_t *queueNum);
static void addDHCPOption(struct DHCPOptList *list, const char *string);

struct Config *conf_parseOpts(int argc, char **argv)
{
	struct DHCPOptList *dhcpOptList = dhcpOpt_createList();
	if (!dhcpOptList)
	{
		fputs("Failed to allocate memory for DHCP option list\n", stderr);
		exit(EXIT_FAILURE);
	}

	enum LongOnlyOpts {
		ForwardOnFail = 1000,
	};

	struct Config *config = createDefaultConfig();
	const struct option options[] =
	{
		{ "debug", no_argument, NULL, 'd' },
		{ "foreground", no_argument, NULL, 'f' },
		{ "forward-on-fail", no_argument, NULL, ForwardOnFail },
		{ "help", no_argument, NULL, 'h' },
		{ "ignore-existing-opt", no_argument, NULL, 'i' },
		{ "option", required_argument, NULL, 'o' },
		{ "pid-file", optional_argument, NULL, 'p' },
		{ "queue", required_argument, NULL, 'q' },
		{ "remove-existing-opt", no_argument, NULL, 'r' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 },
	};

	int dFlagCount = 0;
	int fFlagCount = 0;
	int fwdOnFailFlagCount = 0;
	int iFlagCount = 0;
	int oFlagCount = 0;
	int pFlagCount = 0;
	int qFlagCount = 0;
	int rFlagCount = 0;

	for (;;)
	{
		int opt = getopt_long(argc, argv, "dfhio:p::q:rv", options, NULL);

		/* Parsing finished: */
		if (opt == -1)
			break;

		switch (opt)
		{
			case 'd':
				++dFlagCount;
				config->debug = true;
				break;

			case 'f':
				++fFlagCount;
				config->foreground = true;
				break;

			case ForwardOnFail:
				++fwdOnFailFlagCount;
				config->fwdOnFail = true;
				break;

			case 'h':
				printHelp(argv[0]);
				dhcpOpt_destroyList(dhcpOptList);
				conf_destroy(config);
				exit(EXIT_SUCCESS);
				break;

			case 'i':
				++iFlagCount;
				config->ignoreExistOpt = true;
				break;
				
			case 'p':
				++pFlagCount;
				if (pFlagCount > 1)
					break;
				{
					const char *src = optarg ? optarg : defaultPIDFilePath;
					size_t pidFilePathLen = strlen(src);
					config->pidFile = malloc(pidFilePathLen + 1);
					if (!config->pidFile)
					{
						fputs("Could not allocate space for PID file name\n", stderr);
						exit(EXIT_FAILURE);
					}
					strcpy(config->pidFile, src);
				}
				break;

			case 'o':
				++oFlagCount;
				addDHCPOption(dhcpOptList, optarg);
				break;

			case 'q':
				++qFlagCount;
				if (parseQueueNum(optarg, &config->queue))
				{
					fprintf(stderr, "Invalid queue number: %s\n", optarg);
					printUsage(argv[0]);
					exit(EXIT_FAILURE);
				}
				break;

			case 'r':
				++rFlagCount;
				config->removeExistOpt = true;
				break;

			case 'v':
				printVersion(argv[0]);
				dhcpOpt_destroyList(dhcpOptList);
				conf_destroy(config);
				exit(EXIT_SUCCESS);
				break;

			default:
				printUsage(argv[0]);
				exit(EXIT_FAILURE);
				break;
		}
	}

	if (
			dFlagCount > 1 ||
			fFlagCount > 1 ||
			fwdOnFailFlagCount > 1 ||
			iFlagCount > 1 ||
			pFlagCount > 1 ||
			qFlagCount > 1 ||
			rFlagCount > 1
			)
	{
		fputs("More than one option of a kind (not -o) was provided\n", stderr);
		printUsage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!qFlagCount)
	{
		fputs("Queue number required\n", stderr);
		printUsage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!oFlagCount)
	{
		fputs("At least one DHCP option is required\n", stderr);
		printUsage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (iFlagCount && rFlagCount)
	{
		fputs("Both -i and -r cannot be used at the same time\n", stderr);
		printUsage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (argc - optind > 0)
	{
		fputs("No non-option arguments expected\n", stderr);
		printUsage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (oFlagCount)
	{
		/* Add obligatory DHCP end option and serialise options: */
		if (dhcpOpt_serialise(dhcpOptList, &config->dhcpOpts, &config->dhcpOptsSize))
		{
			fputs("Failed to create DHCP option list\n", stderr);
			exit(EXIT_FAILURE);
		}
		/* Create an array of just the DHCP option codes: */
		if (dhcpOpt_optCodes(dhcpOptList, &config->dhcpOptCodes, &config->dhcpOptCodeCount))
		{
			fputs("Failed to create DHCP option code list\n", stderr);
			exit(EXIT_FAILURE);
		}

		dhcpOpt_destroyList(dhcpOptList);
	}

	return config;
}

void conf_destroy(struct Config *config)
{
	if (!config)
		return;

	free(config->pidFile);
	free(config->dhcpOpts);
	free(config->dhcpOptCodes);
	free(config);
}

static struct Config *createDefaultConfig()
{
	struct Config *config = malloc(sizeof(*config));
	if (!config)
	{
		fputs("Could not allocate space for configuration object\n", stderr);
		exit(EXIT_FAILURE);
	}
	*config = (struct Config) {0};

	return config;
}

static void printUsage(const char *programName)
{
	int progNameLen = strlen(programName);
	printf(
			"%s – DHCP option injector\n"
         "Usage: %s [-d] [-f] [--forward-on-fail] [-i|-r] [-p [pid_file]] \n"
			"       %*s -q queue_num -o dhcp_option [-o dhcp_option] …\n"
			"       %s -h | -v\n"
			,
			programName,
			programName,
			progNameLen, "",
			programName
			);
}

static void printHelp(const char *programName)
{
	printUsage(programName);
	printf(
			"\n"
         "  -d, --debug                Make %s tell you as much as possible\n"
         "                             about what it does and tries to do\n"
         "  -f, --foreground           Prevent %s from running in the\n"
         "                             background\n"
			"      --forward-on-fail      If the process of injecting options should\n"
			"                             fail, let the unaltered DHCP packet pass\n"
			"                             through. The default behaviour is to drop\n"
			"                             the packet if options could not be injected\n"
         "  -h, --help                 Print this help text\n"
			"  -i, --ignore-existing-opt  Ignore existing DHCP options, otherwise\n"
			"                             drop the packet unless --remove-exisiting-opt\n"
			"                             is also provided\n"
			"  -o, --option dhcp_option   DHCP option to inject as a hex string,\n"
			"                             where the first byte indicates the option\n"
			"                             code. The option length field is automatically\n"
			"                             calculatad and must be omitted. Several\n"
			"                             options may be injected\n"
			"  -p, --pid-file [file]      Write PID to file, using specified path\n"
			"                             or a default sensible location\n"
			"  -q, --queue queue_num      Netfilter queue number to use\n"
			"  -r, --remove-existing-opt  Remove existing DHCP options of the same\n"
			"                             kind as those to be injected\n"
         "  -v, --version              Display version\n"
			"\n"
			"%s takes a packet from a netfilter queue, ensures that it is a\n"
			"BOOTP/DHCP request, and injects additional DHCP options before\n"
			"accepting the packet. The following criteria must be fulfilled for\n"
			"%s to touch a packet:\n"
			" - The UDP packet must be BOOTP packet with a DHCP cookie\n"
			" - The UDP packet cannot be fragmented\n"
			"\n"
			"Packets given to %s's queue are matched against protocol UDP\n"
			"and port 67/68. The packet is then assumed to be a BOOTP message. If\n"
			"it has the correct DHCP magic cookie value, its exisiting DHCP\n"
			"options will be parsed. If the packet is not deemed a valid DHCP\n"
			"packet, it will be ignored and accepted. If it is a valid DHCP packet,\n"
			"it cannot be fragmented. If it is, it will be dropped.\n"
			"\n"
			"All the DHCP options specified with the -o/--option flag will be\n"
			"added before the terminating option (end option, 255). The packet is\n"
			"padded if necessary and sent back to netfilter. The IPv4 header\n"
			"checksum is recalculated, but the UDP checksum is set to 0 (disabled).\n"
			"None of the added options are checked for whether they are valid, or\n"
			"whether the option codes are valid. Options are currently not\n"
			"(automatically) padded individually, but they can be manually padded\n"
			"by adding options with code 0 (one option per pad byte). This special\n"
			"option is the only option that does not have any payload (the end\n"
			"option, 255, cannot be manually added). Padding individual options\n"
			"should not be necessary.\n"
			"\n"
			"The option hex string is written as a series of two-digit pairs,\n"
			"optionally delimited by one or more non-hexadecimal characters:\n"
			"'466A6173','46 6A 61 73', '46:6A:61:73' etc. There is a maximum limit\n"
			"of 256 bytes per option, excluding the option code (the first byte)\n"
			"and the automatically inserted length byte. At least one option must\n"
			"be provided.\n"
			"\n"
			"If the packet already contains a DHCP option that is to be injected\n"
			"(matched by code), the behaviour depends on the command line options\n"
			"--ignore-existing-opt and --remove-existing-opt:\n"
			"   (none)   The packet will be dropped\n"
			"   -i       The existing options are ignored and the injected options\n"
			"            are added\n"
			"   -r       Any existing options are removed and the injected options\n"
			"            are added.\n"
			"\n"
			"Note that injected options will not be injected in the same place as\n"
			"those that may have been removed if using -r. However, this should not\n"
			"matter\n"
			"\n"
			"This utility allows you to do things that you probably should not do.\n"
			"Be good and leave packets alone.\n"
         , programName, programName, programName, programName, programName);
}

static void printVersion(const char *programName)
{
	printf("%s – DHCP option injector, version %s\n", programName, DHCPOPTINJ_VERSION);
}

static int parseQueueNum(const char *string, uint16_t *queueNum)
{
	char *lastCh;
	long int num = strtol(string, &lastCh, 10);
	if (num == LONG_MAX || *lastCh != '\0' || num < 0 || num >= UINT16_MAX)
		return 1;

	*queueNum = num;
	return 0;
}

static void addDHCPOption(struct DHCPOptList *list, const char *string)
{
	/* Make room for length byte and payload */
	uint8_t buffer[1 + 256];
	uint16_t length = 0;
	for (size_t i = 0; i < strlen(string) && length < sizeof(buffer);)
	{
		if (isxdigit(string[i]) && sscanf(&string[i], "%2hhx", &buffer[length]) == 1)
		{
			i += 2;
			++length;
		}
		else
			++i;
	}
	uint16_t optCode = buffer[0];

	if (optCode == DHCPOPT_END)
	{
		fputs("The DHCP end option (255) cannot be manually added", stderr);
		exit(EXIT_FAILURE);
	}
	else if (optCode == DHCPOPT_PAD)
		length = 1;
	else
	{
		if (length < 2)
		{
			fprintf(stderr, "DHCP option string too short (payload expected): %s\n", 
					string);
			exit(EXIT_FAILURE);
		}
	}

	if (dhcpOpt_add(list, optCode, buffer + 1, length - 1))
	{
		fputs("Failed to add DHCP option\n", stderr);
		exit(EXIT_FAILURE);
	}
}
