FROM 	debian:stable-slim
USER 	root
ENV	DEBIAN_FRONTEND=noninteractive
COPY	dnsmasq.conf /etc/
COPY	test-dhcpoptinj /usr/sbin/
RUN	\
		# Allow contrib and non-free:
		sed -ri 's/main\s*$/main contrib non-free/' /etc/apt/sources.list && \
		apt-get update && \
		# Install build dependencies, packages needed for the integration test
		# and some handy utilities for development/debugging:
		apt-get install -y -o Debug::pkgProblemResolver=yes -o Dpkg::Options::='--force-confold' --no-install-recommends \
		# Build dependencies (no need to use mk-build-deps for something so simple):
		cmake build-essential libnetfilter-queue-dev \
		# Stuff needed for the test:
		rsyslog iproute2 isc-dhcp-client iptables dnsmasq  \
		# Other handy stuff for debugging:
		vim screen bash-completion valgrind gdb wireshark-common tshark && \
		# Start syslog so that we have some logs to look at:
		service rsyslog start
