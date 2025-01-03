/*
 Copyright 2013-2015 Alexander Wittig. All rights reserved.
 
 Redistribution and use in source and binary forms, with or without 
 modification, are permitted provided that the following conditions are met:
 
 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.
 
 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
*/

/* Low level firewall functionality */

// Initialize firewall
int fw_init( );

// Close firewall
int fw_close( );

// Add an address and associated value to a table
int fw_add( struct sockaddr *addr, socklen_t addrlen, u_int32_t value, u_int16_t table );

// Remove an address from a table
int fw_del( struct sockaddr *addr, socklen_t addrlen, u_int16_t table );

// List all addresses and associated values in a table using a callback function
int fw_list( void (*callback)(struct sockaddr *addr, socklen_t addrlen, u_int32_t, u_int16_t), u_int16_t table );


/* Higher level utility functions */

// read a line from a file and remove the trailing newline
ssize_t readline( char **line, size_t *size, FILE *f );

// check if the given address matches one of our local interfaces
int isLocal( struct sockaddr *sa );

// refresh list of local interface addresses
void updateLocalInterfaces( );

// Add the given host (DNS name or IP address) to firewall table.
// If rt>0 it specifies the number of seconds the host is blocked for, which is
// used in the log messages.
// If bl is non-zero, there is no check to prevent blocking local IPs
int addHostLong( const char* host, uint32_t value, uint32_t table, time_t rt, int bl );

// Add the given host (DNS name or IP address) to firewall table
int addHost( const char* host, uint32_t value, uint32_t table );

