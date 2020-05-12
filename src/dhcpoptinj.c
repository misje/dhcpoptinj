/* 
 * Copyright © 2015–2020 Andreas Misje
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

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>
#include "config.h"
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <libgen.h>
#include "ipv4.h"
#include "udp.h"
#include "dhcp.h"
#include <inttypes.h>

#define MIN_BOOTP_SIZE 300

#pragma pack(1)
struct Packet
{
	struct IPv4Header ipHeader;
	struct UDPHeader udpHeader;
	struct BootP bootp;
};
#pragma pack()

enum MangleResult
{
	Mangle_OK = 0,
	Mangle_mallocFail,
	Mangle_optExists,
};

/* Somewhat arbitrary, feel free to change */
#define MAX_PACKET_SIZE 2048

/* The netfilter queue length 20 is also arbitrary. Hopefully it is
 * sufficient. */
static const uint32_t maxQueueLen = 20;
static struct Config *config;
static bool daemonised;
static sig_atomic_t escapeMainLoop;
static sig_atomic_t signalCaught;

static int inspectPacket(struct nfq_q_handle *queue, struct nfgenmsg *pktInfo, 
		struct nfq_data *pktData, void *userData);
static bool packetIsComplete(const uint8_t *data, size_t size);
static bool packetIsDHCP(const uint8_t *data);
/* Inject DHCP options into DHCP packet */
static enum MangleResult manglePacket(const uint8_t *origData, size_t origDataSize,
		uint8_t **newData, size_t *newDataSize);
static enum MangleResult mangleOptions(const uint8_t *origData, size_t origDataSize,
		uint8_t *newData, size_t *newDataSize);
/* Write a message to syslog or standard stream, depending on whether the
 * process is run as a daemon or not */
static void logMessage(int priority, const char *format, ...);
static void simplifyProgramName(char *programName);
static void writePID(void);
static void removePIDFile(void);
static void destroyConfig(void);
static void initSignalHandler(void);
static void setEscapeMainLoopFlag(int signal);
static void initLog(const char *programName);
/* Debug-print all options to inject */
static void debugLogOptions(void);
/* Very simple check of the provided option codes, warning user if something
 * looks incorrect */
static void inspectOptions(void);
/* Debug-print packet header */
static void debugLogPacketHeader(const uint8_t *data, size_t size);
/* Debug-print packet's existing DHCP options */
static void debugLogOptionFound(const struct DHCPOption *option);
static void debugLogOption(const char *action, const struct DHCPOption *option);
static void debugLogInjectedOptions(void);

int main(int argc, char *argv[])
{
	simplifyProgramName(argv[0]);
	config = conf_parseOpts(argc, argv);
	initLog(argv[0]);

	debugLogOptions();
	inspectOptions();

	logMessage(LOG_DEBUG, "Initialising netfilter queue\n");

	struct nfq_handle *nfq = nfq_open();
	if (!nfq)
	{
		/* Most likely causes are insufficient permissions (missing
		 * CAP_NET_ADMIN capability) or an another process already bound to the
		 * same queue. */
		logMessage(LOG_ERR, "Failed to initialise netfilter queue library: %s\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}
	nfq_unbind_pf(nfq, AF_INET);
	if (nfq_bind_pf(nfq, AF_INET) < 0)
	{
		logMessage(LOG_ERR, "Failed to bind queue handler to AF_INET: %s\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct nfq_q_handle *queue = nfq_create_queue(nfq, config->queue, &inspectPacket, 
			NULL);
	if (!queue)
	{
		logMessage(LOG_ERR, "Failed to create netfilter queue for queue %d: %s\n",
				config->queue, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (nfq_set_mode(queue, NFQNL_COPY_PACKET, MAX_PACKET_SIZE) < 0)
	{
		logMessage(LOG_ERR, "Failed to set netfilter queue mode: %s\n", strerror(
					errno));
		exit(EXIT_FAILURE);
	}

	if (nfq_set_queue_maxlen(queue, maxQueueLen) < 0)
	{
		logMessage(LOG_ERR, "Failed to set netfilter queue length: %s\n", strerror(
					errno));
		exit(EXIT_FAILURE);
	}

	if (!config->foreground)
	{
		logMessage(LOG_DEBUG, "Daemonising\n");
		if (daemon(false, false))
		{
			logMessage(LOG_ERR, "Failed to daemonise: daemon() failed: %s\n", 
					strerror(errno));
			exit(EXIT_FAILURE);
		}
		umask(022);
		daemonised = true;
	}

	initSignalHandler();
	writePID();

	if (config->debug)
		logMessage(LOG_DEBUG, "Initialisation completed. Waiting for packets to "
				"mangle on queue %" PRIu16 "\n", config->queue);
	else
		logMessage(LOG_INFO, "Started\n");

	int exitCode = EXIT_SUCCESS;
	int queueFd = nfq_fd(nfq);
	for (; !escapeMainLoop; )
	{
		char packet[MAX_PACKET_SIZE] __attribute__((aligned));
		ssize_t bytes = recv(queueFd, packet, sizeof(packet), 0);
		if (bytes < -1)
		{
			logMessage(LOG_ERR, "Failed to retrieve packet: %s\n", strerror(errno));
			exitCode = EXIT_FAILURE;
			break;
		}
		else if (bytes > 0)
		{
			logMessage(LOG_DEBUG, "Received %zd bytes\n", bytes);
			if (nfq_handle_packet(nfq, packet, bytes))
				logMessage(LOG_WARNING, "Failed to handle packet: %s\n", strerror(errno));
		}
	}

	if (signalCaught)
	{
		const char *signalName = 
			signalCaught == SIGINT ? "SIGINT" : 
			signalCaught == SIGTERM ? "SIGTERM" : 
			signalCaught == SIGHUP ? "SIGHUP" : "??";

		logMessage(LOG_NOTICE, "Caught signal %s\n", signalName);
	}

	logMessage(LOG_DEBUG, "Destroying netfilter queue\n");
	nfq_destroy_queue(queue);

	/* According to libnetfilter_queue's nfqnl_test.c example, nfq_unbind_pf(…)
	 * should NOT be called during clean up. */
	nfq_close(nfq);

	logMessage(LOG_NOTICE, "Exiting\n");
	removePIDFile();
	destroyConfig();

	return exitCode;
}

static int inspectPacket(struct nfq_q_handle *queue, struct nfgenmsg *pktInfo, 
		struct nfq_data *pktData, void *userData)
{
	(void)pktInfo;
	(void)userData;

	uint8_t *packet;
	ssize_t size = nfq_get_payload(pktData, &packet);
	if (size < 0)
	{
		logMessage(LOG_WARNING, "Failed to retrieve packet from queue: %s\n",
				strerror(errno));
		return 1;
	}

	struct nfqnl_msg_packet_hdr *metaHeader = nfq_get_msg_packet_hdr(pktData);
	if (!packetIsComplete(packet, (size_t)size))
	{
		logMessage(LOG_INFO, "Dropping the packet because it is incomplete\n");
		return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_DROP, 0, NULL);
	}
	if (!packetIsDHCP(packet))
	{
		logMessage(LOG_DEBUG, "Ignoring non-DHCP packet\n");
		return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_ACCEPT, 0, NULL);
	}
	/* We do not have the logic needed to support fragmented packets: */
	if (ipv4_packetFragmented(&((const struct Packet *)packet)->ipHeader))
	{
		uint32_t verdict = config->fwdOnFail ? NF_ACCEPT : NF_DROP;
		if (config->fwdOnFail)
			logMessage(LOG_INFO, "Ignoring fragmented packet\n");
		else
			logMessage(LOG_INFO, "Dropping the packet because it is fragmented\n");
		
		return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), verdict, 0, NULL);
	}
	if (config->debug)
		debugLogPacketHeader(packet, (size_t)size);

	logMessage(LOG_INFO, "Mangling packet\n");

	uint8_t *mangledData = NULL;
	size_t mangledDataSize = 0;
	enum MangleResult result = manglePacket(packet, (size_t)size, &mangledData,
			&mangledDataSize);
	if (result == Mangle_mallocFail)
	{
		logMessage(LOG_WARNING, "Failed to allocate memory for mangled packet\n");
		uint32_t verdict = config->fwdOnFail ? NF_ACCEPT : NF_DROP;
		return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), verdict, 0, NULL);
	}
	else if (result == Mangle_optExists)
	{
		logMessage(LOG_INFO, "Dropping the packet because option already exists\n");
		return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_DROP, 0, NULL);
	}
	else if (result != Mangle_OK)
	{
		logMessage(LOG_ERR, "Internal error: unexpected return value from manglePacket(): %d\n",
				result);
		uint32_t verdict = config->fwdOnFail ? NF_ACCEPT : NF_DROP;
		return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), verdict, 0, NULL);
	}

	if (config->debug)
		logMessage(LOG_DEBUG, "Sending mangled packet\n");

	int res = nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_ACCEPT, 
			mangledDataSize, mangledData);
	free(mangledData);
	return res;
}

static bool packetIsComplete(const uint8_t *data, size_t size)
{
	if (size < sizeof(struct IPv4Header))
		return false;

	const struct Packet *packet = (const struct Packet *)data;
	return packet->ipHeader.totalLen >= sizeof(*packet);
}

static bool packetIsDHCP(const uint8_t *data)
{
	const struct Packet *packet = (const struct Packet *)data;

	if (packet->ipHeader.protocol != IPPROTO_UDP)
		return false;

	uint16_t destPort = ntohs(packet->udpHeader.destPort);
	if (!(destPort == 67 || destPort == 68))
		return false;
	if (packet->udpHeader.length < sizeof(struct UDPHeader) + sizeof(struct BootP))
		return false;

	const struct BootP *dhcp = &packet->bootp;
	if (ntohl(dhcp->cookie) != DHCP_MAGIC_COOKIE)
		return false;

	return true;
}

static enum MangleResult manglePacket(const uint8_t *origData, size_t origDataSize,
		uint8_t **newData, size_t *newDataSize)
{
	const struct Packet *origPacket = (const struct Packet *)origData;
	size_t ipHdrSize = ipv4_headerLen(&origPacket->ipHeader);
	size_t udpHdrSize = sizeof(struct UDPHeader);
	size_t headersSize = ipHdrSize + udpHdrSize + sizeof(struct BootP);
	/* Allocate size for a new packet, slightly larger than needed in order to
	 * avoid reallocation.: */
	*newDataSize = origDataSize + config->dhcpOptsSize + 1; /* room for padding */
	size_t newPayloadSize = *newDataSize - ipHdrSize - udpHdrSize;
	/* Ensure that the DHCP packet (the BOOTP header and payload) is at least
	 * MIN_BOOTP_SIZE bytes long (as per the RFC 1542 requirement): */
	if (newPayloadSize < MIN_BOOTP_SIZE)
		*newDataSize += MIN_BOOTP_SIZE - newPayloadSize;

	*newData = malloc(*newDataSize);
	if (!*newData)
		return Mangle_mallocFail;

	/* Copy 'static' data (everything but the DHCP options) from original
	 * packet: */
	memcpy(*newData, origPacket, headersSize);
	enum MangleResult result = mangleOptions(origData, origDataSize, *newData, 
			newDataSize);
	if (result != Mangle_OK)
	{
		free(*newData);
		return result;
	}

	/* Recalculate actual size (and potential padding) after mangling options
	 * (the initially calculated size is possibly slightly too large, since it
	 * could not forsee how many bytes of DHCP options that was going to be
	 * removed; however, the header size fields need to be correct): */
	newPayloadSize = *newDataSize - ipHdrSize - udpHdrSize;
	size_t padding = (2 - (newPayloadSize % 2)) % 2;
	if (newPayloadSize < MIN_BOOTP_SIZE)
		padding = MIN_BOOTP_SIZE - newPayloadSize;

	newPayloadSize += padding;
	*newDataSize = ipHdrSize + udpHdrSize + newPayloadSize;

	struct Packet *newPacket = (struct Packet *)*newData;
	struct IPv4Header *ipHeader = &newPacket->ipHeader;
	ipHeader->totalLen = htons(*newDataSize);
	ipHeader->checksum = 0;
	ipHeader->checksum = ipv4_checksum(ipHeader);

	struct UDPHeader *udpHeader = &newPacket->udpHeader;
	udpHeader->length = htons(udpHdrSize + newPayloadSize);
	udpHeader->checksum = 0;

	if (padding && config->debug)
		logMessage(LOG_DEBUG, "Padding with %zu byte(s) to meet minimal BOOTP payload "
				"size\n", padding);

	/* Pad to (at least) MIN_BOOTP_SIZE bytes: */
	for (size_t i = *newDataSize - padding; i < *newDataSize; ++i)
		(*newData)[i] = DHCPOPT_PAD;

	return Mangle_OK;
}

static enum MangleResult mangleOptions(const uint8_t *origData, size_t origDataSize,
		uint8_t *newData, size_t *newDataSize)
{
	/* Start with position of the first DHCP option: */
	size_t origOffset = offsetof(struct Packet, bootp) + sizeof(struct BootP);
	size_t newOffset = origOffset;
	size_t padCount = 0;
	while (origOffset < origDataSize)
	{
		const struct DHCPOption *option = (const struct DHCPOption *)(origData + origOffset);
		size_t optSize =
			option->code == DHCPOPT_PAD || option->code == DHCPOPT_END ? 1
			: sizeof(struct DHCPOption) + option->length;

		if (config->debug)
		{
			if (option->code == DHCPOPT_PAD)
				++padCount;
			else
			{
				if (padCount)
					logMessage(LOG_DEBUG, "Found %zu PAD options (removing)\n", padCount);

				debugLogOptionFound(option);
				padCount = 0;
			}
		}

		if (option->code == DHCPOPT_END)
			break;
		/* If existing options are to be ignored and not removed, just copy
		 * them: */
		else if (config->ignoreExistOpt && !config->removeExistOpt)
		{
			if (config->debug)
				logMessage(LOG_DEBUG, " (copying)\n");

			memcpy(newData + newOffset, option, optSize);
			newOffset += optSize;
		}
		/* Otherwise we need to check whether one of the injected options are
		 * already present: */
		else
		{
			bool optFound = false;
			if (option->code != DHCPOPT_END)
				for (size_t i = 0; i < config->dhcpOptCodeCount; ++i)
					if (option->code == config->dhcpOptCodes[i])
					{
						optFound = true;
						break;
					}

			/* If the option already exists in original payload, but is not to be
			 * removed, and ignore command line option is not provided, drop
			 * packet: */
			if (optFound && !config->removeExistOpt && !config->ignoreExistOpt)
			{
				if (config->debug)
					logMessage(LOG_DEBUG, " (conflict)\n");

				return Mangle_optExists;
			}
			/* Copy option if it is not to be removed: */
			else if ((optFound && !config->removeExistOpt) || !optFound)
			{
				if (config->debug)
					logMessage(LOG_DEBUG, " (copying)\n");

				memcpy(newData + newOffset, option, optSize);
				newOffset += optSize;
			}
			else if (config->debug)
				logMessage(LOG_DEBUG, " (removing)\n");
		}
		origOffset += optSize;
	}

	if (config->debug)
		debugLogInjectedOptions();

	/* Inject DHCP options: */
	for (size_t i = 0; i < config->dhcpOptsSize; ++i)
		newData[newOffset + i] = config->dhcpOpts[i];

	newOffset += config->dhcpOptsSize;

	if (config->debug)
		logMessage(LOG_DEBUG, "Inserting END option\n");

	/* Finally insert the END option: */
	newData[newOffset++] = DHCPOPT_END;
	/* Update (reduce) packet size: */
	*newDataSize = newOffset;
	return Mangle_OK;
}

/* Instruct clang that "format" is a printf-style format parameter to avoid
 * non-literal format string warnings in clang: */
__attribute__((__format__ (__printf__, 2, 0)))
static void logMessage(int priority, const char *format, ...)
{
	if (priority == LOG_DEBUG && !config->debug)
		return;

	va_list args1, args2;
	va_start(args1, format);
	va_copy(args2, args1);

	if (config->foreground || !daemonised)
	{
		FILE *f = stderr;
		if (priority == LOG_NOTICE || priority == LOG_INFO || priority == LOG_DEBUG)
			f = stdout;
		
		/* NOLINTNEXTLINE(clang-analyzer-valist.Uninitialized) */
		vfprintf(f, format, args1);
	}
	va_end(args1);

	if (!config->foreground)
		vsyslog(priority, format, args2);

	va_end(args2);
}

static void simplifyProgramName(char *programName)
{
	char *simplifiedName = basename(programName);
	size_t len = strlen(simplifiedName);
	memmove(programName, simplifiedName, len);
	programName[len] = '\0';
}

static void writePID(void)
{
	if (!config->pidFile)
		return;

	pid_t pid = getpid();
	logMessage(LOG_DEBUG, "Writing PID %ld to %s\n", (long)pid, config->pidFile);

	FILE *f = fopen(config->pidFile, "w");
	if (!f)
	{
		logMessage(LOG_ERR, "Failed to write PID to %s: %s\n", config->pidFile,
				strerror(errno));
		exit(EXIT_FAILURE);
	}
	fprintf(f, "%ld", (long)pid);
	fclose(f);
}

static void removePIDFile(void)
{
	if (config->pidFile)
	{
		logMessage(LOG_DEBUG, "Removing PID file %s\n", config->pidFile);
		unlink(config->pidFile);
	}
}

static void destroyConfig(void)
{
	conf_destroy(config);
}

static void initSignalHandler(void)
{
	logMessage(LOG_DEBUG, "Initialising signal handler\n");

	struct sigaction sigAction = { .sa_handler = &setEscapeMainLoopFlag };

	if (sigaction(SIGTERM, &sigAction, NULL) || sigaction(SIGINT, &sigAction, NULL) ||
			sigaction(SIGHUP, &sigAction, NULL))
	{
		logMessage(LOG_ERR, "Failed to initialise signal handler: %s\n", strerror(
					errno));
		exit(EXIT_FAILURE);
	}
}

static void setEscapeMainLoopFlag(int signal)
{
	signalCaught = signal;
	escapeMainLoop = true;
}

static void initLog(const char *programName)
{
	openlog(programName, 0, LOG_DAEMON);
	if (config->debug)
		setlogmask(LOG_UPTO(LOG_DEBUG));
	else
		setlogmask(LOG_UPTO(LOG_INFO));
}

static void debugLogOptions(void)
{
	if (!config->debug)
		return;

	logMessage(LOG_DEBUG, "%zu DHCP option(s) to inject (with a total of %zu bytes): ",
			config->dhcpOptCodeCount, config->dhcpOptsSize);

	for (size_t i = 0; i < config->dhcpOptCodeCount; ++i)
	{
		uint8_t code = config->dhcpOptCodes[i];
		bool atEnd = i == config->dhcpOptCodeCount - 1;
		const char *delim = atEnd ? "\n" : ", ";
		logMessage(LOG_DEBUG, "%u (0x%02X) (%s)%s", code, code, dhcp_optionString(
					code), delim);
	}
	logMessage(LOG_DEBUG, "Existing options will be %s\n", config->removeExistOpt ?
			"removed" : "left in place");
}

static void inspectOptions(void)
{
	size_t nonSpecialOptCount = 0;
	for (size_t i = 0; i < config->dhcpOptCodeCount; ++i)
	{
		uint8_t code = config->dhcpOptCodes[i];
		if (code != DHCPOPT_PAD && code != DHCPOPT_END)
			++nonSpecialOptCount;
	}

	if (!nonSpecialOptCount)
		logMessage(LOG_WARNING, "Warning: Only padding options added\n");
}

static void debugLogPacketHeader(const uint8_t *data, size_t size)
{
	const struct Packet *packet = (const struct Packet *)data;
	const uint8_t *mac = packet->bootp.clientHwAddr;
	struct IPAddr
	{
		uint8_t o1;
		uint8_t o2;
		uint8_t o3;
		uint8_t o4;
	} __attribute__((packed));

	const struct IPAddr *destIP = (const struct IPAddr *)&packet->ipHeader.destAddr; 

	logMessage(LOG_DEBUG, "Inspecting %zu-byte DHCP packet from "
			"%02X:%02X:%02X:%02X:%02X:%02X to %d.%d.%d.%d:%d\n",
			size,
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
			destIP->o1, destIP->o2, destIP->o3, destIP->o4,
			ntohs(packet->udpHeader.destPort)
			);
}

static void debugLogOptionFound(const struct DHCPOption *option)
{
	if (option->code == DHCPOPT_PAD)
		return;
	else if (option->code == DHCPOPT_END)
		logMessage(LOG_DEBUG,"Found END option %s\n", config->dhcpOptCodeCount ?
				"(removing)" : "(copying)");
	else if (option->code == DHCPOPT_TYPE && option->length == 1)
		logMessage(LOG_DEBUG, "Found option % 3hhd (0x%02hhX) (DHCP message type)        %s",
				option->code, option->code, dhcp_msgTypeString(option->data[0]));
	else
		debugLogOption("Found", option);
}

static void debugLogOption(const char *action, const struct DHCPOption *option)
{
	/* String buffer for hex string (maximum DHCP option length (255) times
	 * three characters (two digits and a space)) */
	char optPayload[UINT8_MAX * 3];
	size_t i = 0;
	for (; i < option->length; ++i)
		sprintf(optPayload + 3*i, "%02X ", option->data[i]);

	/* Remove last space: */
	if (i)
		optPayload[3*i - 1] = '\0';

	const char *optName = dhcp_optionString(option->code);
	size_t optNameLen = strlen(optName);
	const size_t alignedWidth = 24;
	logMessage(LOG_DEBUG, "%s option % 3hhd (0x%02hhX) (%s)%*s with % 3d-byte payload %s",
			action,
			option->code,
			option->code,
			optName,
			(int)(optNameLen > alignedWidth ? 0 : alignedWidth - optNameLen),
			"",
			option->length,
			optPayload);
}

static void debugLogInjectedOptions(void)
{
	for (size_t offset = 0; offset < config->dhcpOptsSize;)
	{
		const struct DHCPOption *option = (const struct DHCPOption *)(&config->dhcpOpts[offset]);
		debugLogOption("Injecting", option);
		logMessage(LOG_DEBUG, "%s", "\n");
		offset += option->code == DHCPOPT_PAD || option->code == DHCPOPT_END ? 1
			: sizeof(struct DHCPOption) + option->length;
	}
}
