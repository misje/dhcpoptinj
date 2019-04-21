/* 
 * Copyright © 2015–2019 Andreas Misje
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
#include <errno.h>
#include <ctype.h>

static const char programName[] = "dhcpoptinj";
static const char defaultPIDFilePath[] = "/var/run/dhcpoptinj.pid";
static const char defaultConfFilePath[] = "/etc/dhcpoptinj.conf";

/* DHCP option lists for later serialisation: One for command line input and
 * one for configuration file(s). They need to be separated so that one source
 * does not override the other; the configuration file may be read in the
 * middle of the command line option parsing. */
static struct DHCPOptList *cmdDHCPOptList, *fileDHCPOptList;

enum Source
{
	SOURCE_CMD_LINE           = 0,
	SOURCE_FILE,
};

enum ConfFileParseOption
{
	PARSE_ALLOW_NOEXIST       = 0,
	PARSE_REQUIRE_EXIST       = 1,
};

/* Definitions for long-only options that cannot be identified with an ASCII
 * character: */
enum LongOnlyOpt {
	ForwardOnFail             = 1000,
};

/* Option definitions used to index options[] and optionCount[]: */
enum Option
{
	OPT_CONF_FILE             = 0,
	OPT_DEBUG,
	OPT_FOREGROUND,
	OPT_FORWARD_ON_FAIL,
	OPT_HELP,
	OPT_IGNORE_EXISTING_OPT,
	OPT_OPTION,
	OPT_PID_FILE,
	OPT_QUEUE,
	OPT_REMOVE_EXISTING_OPT,
	OPT_VERSION,

	OPT_COUNT,
};

static const int sources[] = 
{
	SOURCE_CMD_LINE,
	SOURCE_FILE,
};

static const struct option options[] =
{
	[OPT_CONF_FILE]           = { "conf-file",           optional_argument, NULL, 'c' },
	[OPT_DEBUG]               = { "debug",               no_argument,       NULL, 'd' },
	[OPT_FOREGROUND]          = { "foreground",          no_argument,       NULL, 'f' },
	[OPT_FORWARD_ON_FAIL]     = { "forward-on-fail",     no_argument,       NULL, ForwardOnFail },
	[OPT_HELP]                = { "help",                no_argument,       NULL, 'h' },
	[OPT_IGNORE_EXISTING_OPT] = { "ignore-existing-opt", no_argument,       NULL, 'i' },
	[OPT_OPTION]              = { "option",              required_argument, NULL, 'o' },
	[OPT_PID_FILE]            = { "pid-file",            optional_argument, NULL, 'p' },
	[OPT_QUEUE]               = { "queue",               required_argument, NULL, 'q' },
	[OPT_REMOVE_EXISTING_OPT] = { "remove-existing-opt", no_argument,       NULL, 'r' },
	[OPT_VERSION]             = { "version",             no_argument,       NULL, 'v' },
	[OPT_COUNT]               = {0},
};
/* Count the number of times arguments have been passed on the command line
 * and listed as keywords in the configuration file: */
static unsigned int optionCount[][OPT_COUNT] =
{
	[SOURCE_CMD_LINE]         = {0},
	[SOURCE_FILE]             = {0},
};

static struct Config *createDefaultConfig(void);
static void printUsage(void);
static void printHelp(void);
static void printVersion(void);
static int parseQueueNum(const char *string, uint16_t *queueNum);
static void addDHCPOption(struct DHCPOptList *list, const char *string);
static void parseConfFile(struct Config *config, const char *filePath, int parseOpts);
static void parseOption(struct Config *config, int option, char *arg, enum Source source);
static void validateOptionCombinations(void);
static unsigned int totalOptionCount(int option);
static char *trim(char *text);
static int parseKeyValue(const char *key, const char *value, const char *filePath,
		unsigned lineNo);


struct Config *conf_parseOpts(int argc, char * const *argv)
{
	cmdDHCPOptList = dhcpOpt_createList();
	fileDHCPOptList = dhcpOpt_createList();
	if (!cmdDHCPOptList || !fileDHCPOptList)
	{
		fputs("Failed to allocate memory for DHCP option list\n", stderr);
		exit(EXIT_FAILURE);
	}

	struct Config *config = createDefaultConfig();

	while (true)
	{
		int optVal = getopt_long(argc, argv, "c::dfhio:p::q:rv", options, NULL);

		/* Parsing finished: */
		if (optVal == -1)
			break;

		int option = 0;
		for (; option < OPT_COUNT; ++option)
		{
			/* Look for the option in the option list: */
			if (optVal == options[option].val)
			{
				parseOption(config, option, optarg, SOURCE_CMD_LINE);
				break;
			}
		}
		/* The option was not found and is invalid: */
		if (option == OPT_COUNT)
		{
			printUsage();
			exit(EXIT_FAILURE);
		}
	}

	/* If a config file path was not specified on the command line load the
	 * default file, but do not complain if it does not exist: */
	if (!optionCount[SOURCE_CMD_LINE][OPT_CONF_FILE])
		parseConfFile(config, defaultConfFilePath, PARSE_ALLOW_NOEXIST);

	validateOptionCombinations();

	/* dhcpoptinj does not accept any arguments, only options: */
	if (argc - optind > 0)
	{
		fputs("No non-option arguments expected, but the following was passed: ", stderr);
		for (int i = optind; i < argc; ++i)
			fprintf(stderr, "\"%s\"%s", argv[i], i == argc - 1 ? "\n" : ", ");

		printUsage();
		exit(EXIT_FAILURE);
	}

	/* If no DHCP options were passed on the command line use the options from
	 * the configuration file: */
	struct DHCPOptList *dhcpOptList = dhcpOpt_count(cmdDHCPOptList) ?
		cmdDHCPOptList : fileDHCPOptList;
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
	dhcpOpt_destroyList(cmdDHCPOptList);
	dhcpOpt_destroyList(fileDHCPOptList);

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

static struct Config *createDefaultConfig(void)
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

static void printUsage(void)
{
	int progNameLen = (int)sizeof(programName) - 1;
	printVersion();
	printf(
			"\n"
         "Usage: %s [-df] [--forward-on-fail] [-i|-r] [-p [pid_file]] \n"
			"       %*s [-c [config_file]]\n"
			"       %*s -q queue_num -o dhcp_option [(-o dhcp_option) ...]\n"
			"       %s -h|-v\n"
			,
			programName,
			progNameLen, "",
			progNameLen, "",
			programName
			);
}

static void printHelp(void)
{
	printUsage();
	printf(
			"\n"
			"%s takes a packet from a netfilter queue, ensures that it is a\n"
			"BOOTP/DHCP request, and injects additional DHCP options before\n"
			"accepting the packet. The following criteria must be fulfilled for\n"
			"%s to touch a packet:\n"
			" - The UDP packet must be BOOTP packet with a DHCP cookie\n"
			" - The UDP packet must not be fragmented\n"
			"\n"
			"Packets given to %s's queue are matched against protocol UDP\n"
			"and port 67/68. The packet is then assumed to be a BOOTP message. If\n"
			"it has the correct DHCP magic cookie value, %s will proceed to\n"
			"inject new options (removing existing options if requested). If the\n"
			"packet is not deemed a valid DHCP packet, it will be ignored and accepted.\n"
			"If it is a valid DHCP packet it cannot be fragmented. If it is, it will\n"
			"be dropped.\n"
			"\n"
			"Options:\n"
			"\n"
			"  -c, --conf-file [file]     Specify a different configuration file,\n"
         "                             or skip loading one altogether\n"
         "  -d, --debug                Make %s tell you as much as possible\n"
         "                             about what it does and tries to do\n"
         "  -f, --foreground           Prevent %s from running in the\n"
         "                             background\n"
			"      --forward-on-fail      If the process of injecting options should\n"
			"                             fail, let the unaltered DHCP packet pass\n"
			"                             through. The default behaviour is to drop\n"
			"                             the packet if options could not be injected\n"
         "  -h, --help                 Print this help text\n"
			"  -i, --ignore-existing-opt  Proceed if an injected option already exists\n"
			"                             in the original packet. Unless\n"
			"                             --remove-existing-opt is provided, the\n"
			"                             default behaviour is to drop the packet\n"
			"  -o, --option dhcp_option   DHCP option to inject as a hex string,\n"
			"                             where the first byte indicates the option\n"
			"                             code. The option length field is automatically\n"
			"                             calculated and must be omitted. Several\n"
			"                             options may be injected\n"
			"  -p, --pid-file [file]      Write PID to file, using specified path\n"
			"                             or a default sensible location\n"
			"  -q, --queue queue_num      Netfilter queue number to use\n"
			"  -r, --remove-existing-opt  Remove existing DHCP options of the same\n"
			"                             kind as those to be injected\n"
         "  -v, --version              Display version\n"
			,
		programName,
		programName,
		programName,
		programName,
		programName,
		programName);
	printf(
			"\n"
			"%s will read %s (or the file specified with\n"
			"--conf-file) for options, specified as long option names with values\n"
			"separated by \"=\". \"conf-file\" is forbidden in a configuration file.\n"
			"Options passed on the command line will override options in the\n"
			"configuration file\n"
			"\n"
			"All the DHCP options specified with the -o/--option flag will be\n"
			"added before the terminating option (end option, 255). The packet is\n"
			"padded if necessary and sent back to netfilter. The IPv4 header\n"
			"checksum is recalculated, but the UDP checksum is set to 0 (disabled).\n"
			"None of the added options are checked for whether they are valid, or\n"
			"whether the option codes are valid. Options are currently not\n"
			"(automatically) padded individually, but they can be manually padded\n"
			"by adding options with code 0 (one pad byte per option). This special\n"
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
			"matter.\n"
			"\n"
			"This utility allows you to do things that you probably should not do.\n"
			"Be good and leave packets alone.\n"
         ,
		programName,
		defaultConfFilePath);
}

static void printVersion(void)
{
	printf(
			"%s - DHCP option injector, version %s\n"
			"Copyright (C) 2015-2019 by Andreas Misje\n"
			"\n"
			"%s comes with ABSOLUTELY NO WARRANTY. This is free software,\n"
			"and you are welcome to redistribute it under certain conditions. See\n"
			"the GNU General Public Licence for details.\n",
			programName,
			DHCPOPTINJ_VERSION,
			programName);
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
	if (!string)
		return;

	/* Make room for length byte and payload */
	uint8_t buffer[1 + 256];
	size_t length = 0;
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
	if (!length)
		return;

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
			fprintf(stderr, "The DHCP option string is too short (payload expected): %s\n", 
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

static void parseConfFile(struct Config *config, const char *filePath, int parseOpts)
{
	FILE *file = fopen(filePath, "r");
	if (!file && (parseOpts & PARSE_REQUIRE_EXIST))
	{
		fprintf(stderr, "Failed to open configuration file \"%s\": %s\n",
				filePath, strerror(errno));
		exit(EXIT_FAILURE);
	}
	else if (!file)
		return;

	printf("Parsing configuration file \"%s\"\n", filePath);

	unsigned int lineNo = 0;
	char line[1024];
	while (fgets(line, sizeof(line), file))
	{
		++lineNo;
		{
			/* If the comment character '#' is found, terminate the string at
			 * this position: */
			char *commentStart = strchr(line, '#');
			if (commentStart)
				*commentStart = '\0';
		}
		char *key = line;
		/* Keywords and values are separated by '=': */
		char *value = strchr(line, '=');
		/* Ensure that the "value" pointer is not at the end of the buffer,
		 * since we aim to access data past it: */
		if (value && value - key < (ptrdiff_t)(sizeof(line) - 1))
		{
			*value = '\0';
			++value;
			value = trim(value);
		}
		key = trim(key);
		/* Line is a comment. Do not parse: */
		if (!*key)
			continue;

		int option = parseKeyValue(key, value, filePath, lineNo);
		parseOption(config, option, value, SOURCE_FILE);
	}

	fclose(file);
}

static void parseOption(struct Config *config, int option, char *arg, enum Source source)
{
	/* Do not override command line options from configuration file: */
	if (source == SOURCE_FILE && optionCount[SOURCE_CMD_LINE][option])
		return;

	++optionCount[source][option];
	switch (option)
	{
		case OPT_CONF_FILE:
			/* An empty argument is allowed, in which case no file is ever loaded
			 * (including the default one), so do nothing now that optionCount
			 * has been incremented: */
			if (arg)
				parseConfFile(config, arg, PARSE_REQUIRE_EXIST);

			break;

		case OPT_DEBUG:
			config->debug = true;
			break;

		case OPT_FOREGROUND:
			config->foreground = true;
			break;

		case OPT_FORWARD_ON_FAIL:
			config->fwdOnFail = true;
			break;

		case OPT_HELP:
			if (source == SOURCE_FILE)
			{
				fprintf(stderr, "The option \"%s\" doesn't make sense in a configuration "
						"file\n", options[option].name);
				exit(EXIT_FAILURE);
			}
			printHelp();
			dhcpOpt_destroyList(cmdDHCPOptList);
			dhcpOpt_destroyList(fileDHCPOptList);
			conf_destroy(config);
			exit(EXIT_SUCCESS);
			break;

		case OPT_IGNORE_EXISTING_OPT:
			config->ignoreExistOpt = true;
			break;
			
		case OPT_PID_FILE:
			if (config->pidFile)
				break;
			{
				const char *src = arg ? arg : defaultPIDFilePath;
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

		case OPT_OPTION:
			addDHCPOption(source == SOURCE_FILE ? fileDHCPOptList : cmdDHCPOptList, arg);
			break;

		case OPT_QUEUE:
			if (!arg || parseQueueNum(arg, &config->queue))
			{
				fprintf(stderr, "Invalid queue number: %s\n", arg);
				printUsage();
				exit(EXIT_FAILURE);
			}
			break;

		case OPT_REMOVE_EXISTING_OPT:
			config->removeExistOpt = true;
			break;

		case OPT_VERSION:
			if (source == SOURCE_FILE)
			{
				fprintf(stderr, "The option \"%s\" doesn't make sense in a configuration "
						"file\n", options[option].name);
				exit(EXIT_FAILURE);
			}
			printVersion();
			dhcpOpt_destroyList(cmdDHCPOptList);
			dhcpOpt_destroyList(fileDHCPOptList);
			conf_destroy(config);
			exit(EXIT_SUCCESS);
			break;

		default:
			/* Only valid options are passed to this function */
			break;
	}
}

static void validateOptionCombinations(void)
{
	for (size_t source = 0; source < sizeof(sources)/sizeof(sources[0]); ++source)
		for (size_t option = 0; option < OPT_COUNT; ++option)
			/* If an option other than --option is passed more than once, freak out: */
			if (optionCount[source][option] > 1 && option != OPT_OPTION)
			{
				fprintf(stderr, "%s%s can only be %s once\n",
						source == SOURCE_CMD_LINE ? "Option --" : "Keyword ",
						options[option].name,
						source == SOURCE_CMD_LINE ? "passed" : "specified");
				printUsage();
				exit(EXIT_FAILURE);
			}

	if (!totalOptionCount(OPT_QUEUE))
	{
		fputs("Queue number required\n", stderr);
		printUsage();
		exit(EXIT_FAILURE);
	}

	if (!totalOptionCount(OPT_OPTION))
	{
		fputs("At least one DHCP option is required\n", stderr);
		printUsage();
		exit(EXIT_FAILURE);
	}

	if (totalOptionCount(OPT_IGNORE_EXISTING_OPT) && totalOptionCount(
				OPT_REMOVE_EXISTING_OPT))
	{
		fprintf(stderr, "Both %s%s and %s%s cannot be used at the same time\n",
				optionCount[SOURCE_CMD_LINE][OPT_IGNORE_EXISTING_OPT] ? "--" : "",
				options[OPT_IGNORE_EXISTING_OPT].name,
				optionCount[SOURCE_CMD_LINE][OPT_REMOVE_EXISTING_OPT] ? "--" : "",
				options[OPT_REMOVE_EXISTING_OPT].name);
		printUsage();
		exit(EXIT_FAILURE);
	}
}

static unsigned int totalOptionCount(int option)
{
	return optionCount[SOURCE_CMD_LINE][option] + optionCount[SOURCE_FILE][option];
}

static char *trim(char *text)
{
	if (!*text)
		return text;

	/* Trim leading and trailing whitespace and quote characters: */
	for (char *ch = text + strlen(text) - 1;
			isspace((int)*ch) || *ch == '\'' || *ch == '\"'; *ch-- = '\0');
	for (; isspace((int)*text) || *text == '\'' || *text == '\"'; *text++ = '\0');

	return text;
}

static int parseKeyValue(const char *key, const char *value, const char *filePath,
		unsigned lineNo)
{
	for (int option = 0; option < OPT_COUNT; ++option)
	{
		if (strcmp(key, options[option].name))
			continue;

		if (options[option].has_arg == required_argument && !value)
		{
			fprintf(stderr, "Failed to parse \"%s\" at line %u: %s requires an argument\n",
					filePath, lineNo, options[option].name);
			exit(EXIT_FAILURE);
		}
		else if (!options[option].has_arg && value)
		{
			fprintf(stderr, "Failed to parse \"%s\" at line %u: %s does not take an argument\n",
					filePath, lineNo, options[option].name);
			exit(EXIT_FAILURE);
		}

		return option;
	}

	fprintf(stderr, "Failed to parse \"%s\" at line %u: \"%s\" is not a valid keyword\n",
			filePath, lineNo, key);
	exit(EXIT_FAILURE);
	return -1;
}
