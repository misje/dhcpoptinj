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

#include "dhcp.h"

const char *dhcp_msgTypeString(uint8_t msgType)
{
	switch (msgType)
	{
		case 1:
			return "DHCPDISCOVER";
		case 2:
			return "DHCPOFFER";
		case 3:
			return "DHCPREQUEST";
		case 4:
			return "DHCPDECLINE";
		case 5:
			return "DHCPACK";
		case 6:
			return "DHCPNAK";
		case 7:
			return "DHCPRELEASE";
		case 8:
			return "DHCPINFORM";
		default:
			return "??";
	}
}
