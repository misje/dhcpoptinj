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

struct Packet
{
	struct IPv4Header ipHeader;
	struct UDPHeader udpHeader;
	struct BootP bootp;
} __attribute__((packed));

enum DHCPOptFindResult
{
	FindOpt_OK,
	FindOpt_Incomplete,
	FindOpt_NotDHCP,
	FindOpt_Fragmented,
	FindOpt_OptExists,
	FindOpt_Invalid,
};

/* Somewhat arbitrary, feel free to change */
static const int maxPacketSize = 2048;
/* The netfilter queue length 20 is also arbitrary. Hopefully it is
 * sufficient. */
static const int maxQueueLen = 20;
static struct Config *config;
static bool daemonised;
static sig_atomic_t escapeMainLoop;
static sig_atomic_t signalCaught;

static int inspectPacket(struct nfq_q_handle *queue, struct nfgenmsg *pktInfo, 
		struct nfq_data *pktData, void *userData);
/* Find the last DHCP option in packet, the terminating 'end' option, and
 * store its offset from packet start */
static int findDHCPOptTerm(const uint8_t *data, size_t size, size_t *termOptOffset);
/* Inject DHCP options into DHCP packet */
static int manglePacket(const struct Packet *origPacket, struct Packet **newPacket, 
		size_t *newPacketSize, size_t termOptOffset);
/* Write a message to syslog or standard stream, depending on whether the
 * process is run as a daemon or not */
static void logMessage(int priority, const char *format, ...);
static void simplifyProgramName(char *programName);
static void writePID();
static void removePIDFile();
static void destroyConfig();
static void initSignalHandler();
static void setEscapeMainLoopFlag(int signal);
static void initLog(const char *programName);
/* Convert enum DHCPOptFindResult to string */
static const char *findOptResString(int dhcpOptFindResult);
/* Debug-print all options to inject */
static void debugLogOptions();
/* Very simple check of the provided option codes, warning user if something
 * looks incorrect */
static void inspectOptions();
/* Debug-print packet header */
static void debugLogPacket(const struct Packet *packet);
/* Debug-print packet's existing DHCP options */
static void debugLogOption(const struct DHCPOption *option);

int main(int argc, char *argv[])
{
	simplifyProgramName(argv[0]);
	config = conf_parseOpts(argc, argv);
	initLog(argv[0]);

	debugLogOptions();
	inspectOptions();

	logMessage(LOG_DEBUG, "Initialising netfilter queue …\n");

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

	if (nfq_set_mode(queue, NFQNL_COPY_PACKET, maxPacketSize) < 0)
	{
		logMessage(LOG_ERR, "Failed to set netfilter queue mode: %s\n", strerror(
					errno));
		exit(EXIT_FAILURE);
	}

	if (nfq_set_queue_maxlen(queue, 20) < 0)
	{
		logMessage(LOG_ERR, "Failed to set netfilter queue length: %s\n", strerror(
					errno));
		exit(EXIT_FAILURE);
	}

	if (!config->foreground)
	{
		logMessage(LOG_DEBUG, "Daemonising …\n");
		if (daemon(false, false))
		{
			logMessage(LOG_ERR, "Failed to daemonise: daemon() failed: %s\n", 
					strerror(errno));
			exit(EXIT_FAILURE);
		}
		umask(022);
		daemonised = true;
	}
	writePID();

	initSignalHandler();

	if (config->debug)
		logMessage(LOG_DEBUG, "Initialisation completed. Waiting for packets to mangle …\n");
	else
		logMessage(LOG_INFO, "Started\n");

	int exitCode = EXIT_SUCCESS;
	int queueFd = nfq_fd(nfq);
	for (; !escapeMainLoop; )
	{
		char packet[maxPacketSize] __attribute__((aligned));
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

	logMessage(LOG_DEBUG, "Destroying netfilter queue …\n");
	nfq_destroy_queue(queue);

	/* According to libnetfilter_queue's nfqnl_test.c example, nfq_unbind_pf(…)
	 * should NOT be called during clean up. */
	nfq_close(nfq);

	logMessage(LOG_NOTICE, "Exiting …\n");
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
	size_t termOptPos = 0;
	enum DHCPOptFindResult res = findDHCPOptTerm(packet, size, &termOptPos);
	if (res == FindOpt_NotDHCP)
	{
		logMessage(LOG_DEBUG, "Ignoring non-DHCP packet\n");
		return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_ACCEPT, 0, NULL);
	}
	else if (res == FindOpt_OK)
	{
		struct Packet *mangledPacket = NULL;
		size_t mangledPacketSize = 0;
		if (manglePacket((const struct Packet *)packet, &mangledPacket, 
					&mangledPacketSize, termOptPos))
		{
			logMessage(LOG_WARNING, "Failed to allocate memory for mangled packet\n");
			uint32_t verdict = config->fwdOnFail ? NF_ACCEPT : NF_DROP;
			return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), verdict, 0, NULL);
		}

		int res = nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_ACCEPT, 
				mangledPacketSize, (uint8_t *)mangledPacket);
		free(mangledPacket);
		logMessage(LOG_INFO, "Mangling packet\n");
		return res;
	}
	else
	{
		logMessage(LOG_INFO, "Dropping the packet because %s\n", findOptResString(res));
		return nfq_set_verdict(queue, ntohl(metaHeader->packet_id), NF_DROP, 0, NULL);
	}
}

static int findDHCPOptTerm(const uint8_t *data, size_t size, size_t *termOptOffset)
{
	if (size < sizeof(struct IPv4Header))
		return FindOpt_Incomplete;

	const struct Packet *packet = (const struct Packet *)data;

	if (packet->ipHeader.totalLen < sizeof(*packet))
		return FindOpt_Incomplete;
	if (packet->ipHeader.protocol != IPPROTO_UDP)
		return FindOpt_NotDHCP;

	uint16_t destPort = ntohs(packet->udpHeader.destPort);
	if (!(destPort == 67 || destPort == 68))
		return FindOpt_NotDHCP;
	if (packet->udpHeader.length < sizeof(struct UDPHeader) + sizeof(struct BootP))
		return FindOpt_NotDHCP;

	const struct BootP *dhcp = &packet->bootp;
	if (ntohl(dhcp->cookie) != DHCP_MAGIC_COOKIE)
		return FindOpt_NotDHCP;

	/* We do not have the logic needed to support fragmented packets: */
	if (ipv4_packetFragmented(&packet->ipHeader))
		return FindOpt_Fragmented;

	if (config->debug)
		debugLogPacket(packet);

	/* Start with position of the first DHCP option: */
	size_t offset = sizeof(*packet);
	while (offset < size)
	{
		const struct DHCPOption *option = (const struct DHCPOption *)(data + offset);
		if (option->code == DHCPOPT_PAD)
		{
			offset += 1;
			continue;
		}
		else if (option->code == DHCPOPT_END)
		{
			*termOptOffset = (const uint8_t *)option - data;
			return FindOpt_OK;
		}
		else if (config->debug)
			debugLogOption(option);

		offset += sizeof(struct DHCPOption) + option->length;

		if (!config->ignoreExistOpt)
			for (size_t i = 0; i < config->dhcpOptCodeCount; ++i)
				if (option->code == config->dhcpOptCodes[i])
					return FindOpt_OptExists;
	}

	return FindOpt_Invalid;
}

static int manglePacket(const struct Packet *origPacket, struct Packet **newPacket, 
		size_t *newPacketSize, size_t termOptOffset)
{
	size_t ipHdrSize = ipv4_headerLen(&origPacket->ipHeader);
	size_t udpHdrSize = sizeof(struct UDPHeader);
	size_t newPayloadSize = termOptOffset - ipHdrSize - udpHdrSize + config->dhcpOptsSize;
	size_t padding = (2 - (newPayloadSize % 2)) % 2;
	size_t newTotalSize = ipHdrSize + udpHdrSize + newPayloadSize + padding;

	/* Ensure that the DHCP packet (exluding IP header) is at least 300 bytes
	 * long: */
	if (newTotalSize - ipHdrSize < 300)
	{
		size_t extraPadding = 300 - (newTotalSize - ipHdrSize);
		padding += extraPadding;
		newTotalSize += extraPadding;
	}
	*newPacketSize = newTotalSize;
	*newPacket = malloc(newTotalSize);
	if (!newPacket)
		return 1;

	memcpy(*newPacket, origPacket, termOptOffset);

	struct IPv4Header *ipHeader = &(*newPacket)->ipHeader;
	ipHeader->totalLen = htons(newTotalSize);
	ipHeader->checksum = 0;
	ipHeader->checksum = ipv4_checksum(ipHeader);

	struct UDPHeader *udpHeader = &(*newPacket)->udpHeader;
	udpHeader->length = htons(udpHdrSize + newPayloadSize + padding);
	udpHeader->checksum = 0;

	/* Inject DHCP options: */
	for (size_t i = 0; i < config->dhcpOptsSize; ++i)
		((uint8_t *)*newPacket)[termOptOffset + i] = config->dhcpOpts[i];

	/* Pad to (at least) 300 bytes: */
	for (size_t i = 1; i <= padding; ++i)
		((uint8_t *)*newPacket)[newTotalSize - i] = 0;

	return 0;
}

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
		
		vfprintf(f, format, args1);
	}
	va_end(args1);

	if (!config->foreground)
		vsyslog(priority, format, args2);

	va_end(args2);
}

static void simplifyProgramName(char *programName)
{
	size_t strLen = strlen(programName);
	memmove(programName, basename(programName), strLen + 1);
}

static void writePID()
{
	if (!config->pidFile)
		return;

	pid_t pid = getpid();
	logMessage(LOG_DEBUG, "Writing PID %ld to %s …\n", (long)pid, config->pidFile);

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

static void removePIDFile()
{
	if (config->pidFile)
	{
		logMessage(LOG_DEBUG, "Removing PID file %s …\n", config->pidFile);
		unlink(config->pidFile);
	}
}

static void destroyConfig()
{
	conf_destroy(config);
}

static void initSignalHandler()
{
	logMessage(LOG_DEBUG, "Initialising signal handler …\n");

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

static const char *findOptResString(int dhcpOptFindResult)
{
	switch (dhcpOptFindResult)
	{
		case FindOpt_Incomplete:
			return "it is incomplete";
		case FindOpt_Fragmented:
			return "it is fragmented";
		case FindOpt_OptExists:
			return "an option to be injected already exists";
		case FindOpt_Invalid:
			return "the packet is malformed";
		default:
			return "??";
	}
}

static void debugLogOptions()
{
	if (!config->debug)
		return;

	logMessage(LOG_DEBUG, "%u DHCP option(s) to inject (total of %zu bytes): ",
			config->dhcpOptCodeCount, config->dhcpOptsSize);

	for (size_t i = 0; i < config->dhcpOptCodeCount; ++i)
	{
		bool atEnd = i == config->dhcpOptCodeCount - 1;
		const char *delim = atEnd ? "\n" : ", ";
		logMessage(LOG_DEBUG, "%u%s", config->dhcpOptCodes[i], delim);
	}
}

static void inspectOptions()
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

static void debugLogPacket(const struct Packet *packet)
{
	const uint8_t *mac = packet->bootp.clientHwAddr;
	struct IPAddr
	{
		uint8_t o1;
		uint8_t o2;
		uint8_t o3;
		uint8_t o4;
	} __attribute__((packed));

	const struct IPAddr *destIP = (const struct IPAddr *)&packet->ipHeader.destAddr; 

	logMessage(LOG_DEBUG, "Inspecting packet from %02X:%02X:%02X:%02X:%02X:%02X to "
			"%d.%d.%d.%d …\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
			destIP->o1, destIP->o2, destIP->o3, destIP->o4);
}

static void debugLogOption(const struct DHCPOption *option)
{
	if (option->code == DHCPOPT_TYPE && option->length == 1)
		logMessage(LOG_DEBUG, "Found option %hhu (0x%02hhX) (DHCP message type): %s\n",
				option->code, option->code, dhcp_msgTypeString(option->data[0]));
	else
	{
		/* String buffer for hex string (maximum DHCP option length (256) times
		 * three characters (two digits and a space)) */
		char optPayload[256 * 3];
		size_t i = 0;
		for (; i < option->length; ++i)
			sprintf(optPayload + 3*i, "%02X ", option->data[i]);

		/* Remove last space: */
		if (i)
			optPayload[3*i - 1] = '\0';

		logMessage(LOG_DEBUG, "Found option %hhu (0x%02hhX) with payload %s\n",
				option->code, option->code, optPayload);
	}
}
