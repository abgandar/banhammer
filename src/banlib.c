/*
 Copyright 2013-2025 Alexander Wittig. All rights reserved.

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

#include <config.h>

#define _WITH_GETLINE
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ip_fw.h>

extern int loglevel;                    // loglevel, defined in main programs
static struct ifaddrs *ifAddrs = NULL;  // cached list of local interfaces
static int ipfw_socket = -1;            // the socket to the IPFW firewall

// Local constants
static const int BANLIB_DEL = 0;
static const int BANLIB_ADD = 1;

/* Firewall routines */

// local forward declaration
static int fw_table_cmd( int opcode, struct sockaddr* addr, socklen_t addrlen, u_int32_t value, u_int16_t table );

// Inititalize the connection to the firewall.
int fw_init( )
{
    if ( ipfw_socket == -1 )
    {
        if ( (ipfw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW )) < 0 )
            return 1;
    }
    else
        return 2;

    return 0;
}

// Clean up after yourself, the program is about to quit
int fw_close( )
{
    if ( ipfw_socket != -1 )
        close( ipfw_socket );
    return 0;
}

// store an IP address and associated value in the given firewall table, ignore duplicates
int fw_add( struct sockaddr* addr, socklen_t addrlen, u_int32_t value, u_int16_t table )
{
    int rc;

    rc = fw_table_cmd( BANLIB_ADD, addr, addrlen, value, table );
    return rc == 0 ? 0 : (errno == EEXIST ? 2 : 1);
}

// remove a given IP address from the given firewall table, error if not found
int fw_del( struct sockaddr* addr, socklen_t addrlen, u_int16_t table )
{
    int rc;

    rc = fw_table_cmd( BANLIB_DEL, addr, addrlen, 0, table );
    return rc == 0 ? 0 : 1;
}

// internal helper to execute an IPFW table command.
// Opcode is BANLIB_ADD or BANLIB_DEL
static int fw_table_cmd( int opcode, struct sockaddr* addr, socklen_t addrlen, u_int32_t value, u_int16_t table )
{
    ipfw_obj_header *oh;
	ipfw_obj_ctlv *ctlv;
	ipfw_obj_tentry *tent;
    socklen_t l;
    int rc;

    if( ipfw_socket == -1 )
        return -1;

    // prepare IPFW3 command
    l = sizeof(ipfw_obj_header) + sizeof(ipfw_obj_ctlv) + sizeof(ipfw_obj_tentry);
    oh = (ipfw_obj_header*)calloc( 1, l );
    if( !oh ) return -1;
    oh->opheader.opcode = (opcode == BANLIB_ADD) ? IP_FW_TABLE_XADD : IP_FW_TABLE_XDEL;
    oh->opheader.version = 1;
    oh->ntlv.head.type = IPFW_TLV_TBL_NAME;
    oh->ntlv.head.length = sizeof(ipfw_obj_ntlv);
    oh->ntlv.idx = 1;
	oh->ntlv.set = 0;
    oh->ntlv.type = IPFW_TABLE_ADDR;
    snprintf( oh->ntlv.name, sizeof(oh->ntlv.name), "%hu", table );
    oh->idx = 1;

    ctlv = (ipfw_obj_ctlv*)(oh + 1);
    ctlv->count = 1;
    ctlv->head.length = sizeof(*ctlv) + sizeof(*tent);
    //ctlv->flags |= IPFW_CTF_ATOMIC;

    tent = (ipfw_obj_tentry*)(ctlv + 1);
    tent->head.length = sizeof(ipfw_obj_tentry);
    tent->head.flags |= (opcode == BANLIB_ADD) ? IPFW_TF_UPDATE : 0;
    tent->idx = oh->idx;
    tent->v.value.mark = value;
    // set all other values in case this is a legacy table (masked out again by IPFW)
    tent->v.value.tag = value;
    tent->v.value.pipe = value;
    tent->v.value.divert = value;
    tent->v.value.skipto = value;
    tent->v.value.netgraph = value;
    tent->v.value.fib = value;
    tent->v.value.nat = value;
    tent->v.value.nh4 = value;
    tent->v.value.dscp = (uint8_t)value;
    tent->v.value.limit = value;

    switch( addr->sa_family )
    {
        case AF_INET:
            if( addrlen < sizeof(struct in_addr) )
            {
                free( oh );
                return 1;
            }
            tent->subtype = AF_INET;
            tent->masklen = 32;
            tent->k.addr = ((struct sockaddr_in*)addr)->sin_addr;
            break;

#ifdef WITH_IPV6
        case AF_INET6:
            if( addrlen < sizeof(struct in6_addr) )
            {
                free( oh );
                return 1;
            }
            tent->subtype = AF_INET6;
            tent->masklen = 128;
            tent->k.addr6 = ((struct sockaddr_in6*)addr)->sin6_addr;
            break;
#endif

        default:
            free( oh );
            return 1;
    }

    rc = setsockopt( ipfw_socket, IPPROTO_IP, IP_FW3, &(oh->opheader), l );
    free( oh );
    return rc;
}

// Get all IP addresses and associated values in given table and call
// a callback function with each of them.
// Note: The callback may alter the state of the table. This function
// always reflects the unaltered state of the table for all callbacks.
int fw_list( void (*callback)(struct sockaddr*, socklen_t, u_int32_t, u_int16_t), u_int16_t table )
{
    ipfw_obj_header *oh;
    ipfw_xtable_info *ti;
	ipfw_obj_tentry *tent;
    socklen_t l;
    struct sockaddr_in sa4 = { 0 };
#ifdef WITH_IPV6
    struct sockaddr_in6 sa6 = { 0 };
#endif

    if( ipfw_socket == -1 )
        return -1;

    // obtain table info
    l = sizeof(ipfw_obj_header) + sizeof(ipfw_xtable_info);
    if( (oh = (ipfw_obj_header*)calloc( 1, l )) == NULL )
        return 1;
    oh->opheader.opcode = IP_FW_TABLE_XINFO;
    oh->opheader.version = 1;
    oh->ntlv.head.type = IPFW_TLV_TBL_NAME;
    oh->ntlv.head.length = sizeof(ipfw_obj_ntlv);
    oh->ntlv.idx = 1;
	oh->ntlv.set = 0;
    snprintf( oh->ntlv.name, sizeof(oh->ntlv.name), "%hu", table );
    oh->idx = 1;
    if( getsockopt( ipfw_socket, IPPROTO_IP, IP_FW3, &(oh->opheader), &l ) < 0 )
    {
        free( oh );
        return 1;
    }
    ti = (ipfw_xtable_info*)(oh + 1);
    if( ti->type != IPFW_TABLE_ADDR || (ti->vmask & IPFW_VTYPE_MARK) == 0 )     // also accepts VTYPE_LEGACY
    {
        free( oh );
        return 1;
    }
    if( ti->count == 0 )
    {
        free( oh );
        return 0;
    }

    // obtain table entries
    l = sizeof(ipfw_obj_header) + sizeof(ipfw_xtable_info) + ti->size;
    if( (oh = (ipfw_obj_header*)realloc( oh, l )) == NULL )
        return 1;
    oh->opheader.opcode = IP_FW_TABLE_XLIST;
    if( getsockopt( ipfw_socket, IPPROTO_IP, IP_FW3, oh, &l ) < 0 )
    {
        free( oh );
        return 1;
    }

    // call the callback for each address in table
    ti = (ipfw_xtable_info*)(oh + 1);
    tent = (ipfw_obj_tentry*)(ti + 1);
    sa4.sin_family = AF_INET;
#ifdef WITH_IPV6
    sa6.sin6_family = AF_INET6;
#endif
    for( l = 0; l < ti->count; l++ )
    {
        if( tent->subtype == AF_INET )
        {
            sa4.sin_addr = tent->k.addr;
            (*callback)( (struct sockaddr*)&sa4, sizeof(sa4), tent->v.value.mark, table );
        }
#ifdef WITH_IPV6
        else if( tent->subtype == AF_INET6 )
        {
            sa6.sin6_addr = tent->k.addr6;
            (*callback)( (struct sockaddr*)&sa6, sizeof(sa6), tent->v.value.mark, table );
        }
#endif
        tent = (ipfw_obj_tentry*)((caddr_t)tent + tent->head.length);
    }

    free( oh );
    return 0;
}

/* Higher level utility routines */

// read a line from a file and remove the trailing newline
ssize_t readline( char **line, size_t *size, FILE *f )
{
    ssize_t rc;

    rc = getline( line, size, f );
    if( (rc > 0) && ((*line)[rc-1] == '\n') )
    {
        (*line)[rc-1] = '\0';
        rc--;
    }

    return rc;
}

// release list of local interface addresses so they are reloaded when needed
void updateLocalInterfaces( )
{
    if( ifAddrs ) freeifaddrs( ifAddrs );
    ifAddrs = NULL;
}

// check if the given address matches one of our local interfaces
int isLocal( struct sockaddr *sa )
{
    struct ifaddrs *ifa;

    // Check for loopback and supported address family
    switch( sa->sa_family )
    {
        case AF_INET:
            if( IN_LOOPBACK( ((struct sockaddr_in*)sa)->sin_addr.s_addr ) )
                return 1;
            break;

#ifdef WITH_IPV6
        case AF_INET6:
            if( IN6_IS_ADDR_LOOPBACK( &((struct sockaddr_in6*)sa)->sin6_addr ) )
                return 1;
            break;
#endif

        default:
            return 0;
    }

    // load local interfaces if needed
    if( !ifAddrs ) getifaddrs( &ifAddrs );
    ifa = ifAddrs;

    // Check each interface
    while( ifa )
    {
        if( ifa->ifa_addr->sa_family == sa->sa_family )
            switch( sa->sa_family )
            {
                case AF_INET:
                    if( ((struct sockaddr_in*)sa)->sin_addr.s_addr == ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr )
                        return 1;
                    break;

#ifdef WITH_IPV6
                case AF_INET6:
                    if( IN6_ARE_ADDR_EQUAL( &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr, &((struct sockaddr_in6*)sa)->sin6_addr ) )
                        return 1;
                    break;
#endif
            }
        ifa = ifa->ifa_next;
    }

    return 0;
}

// Add the given host (DNS name or IP address) to firewall table.
// If rt>0 it specifies the number of seconds the host is blocked for, which is
// used in the log messages.
// If bl is non-zero, there is no check to prevent blocking local IPs
int addHostLong( const char* host, uint32_t value, uint32_t table, time_t rt, int bl )
{
    struct addrinfo *res = NULL, *ai;
    struct addrinfo hints = { 0 };
    char ip[NI_MAXHOST] = { 0 };
    int rc, err = 0;

    hints.ai_flags = AI_ADDRCONFIG;
    // prevent getaddrinfo from returning various socktype/protocol combinations for the same address
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
#ifndef WITH_IPV6
    // only ask for IPv4 addresses
    hints.ai_family = AF_INET;
#else
    hints.ai_family = PF_UNSPEC;
#endif
    rc = getaddrinfo( host, NULL, &hints, &res );
    if( rc )
    {
        if( loglevel >= 1 )
            sysprintLog( LOG_NOTICE, "Failed to resolve '%s' for blocking: %s (rc=%d)", host, gai_strerror( rc ), rc );
        return -1;
    }

    ai = res;
    while( ai != NULL )
    {
        // pretty-print the IP of the host to block if needed
        if( loglevel >=1 )
            if( getnameinfo( ai->ai_addr, ai->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST ) )
                strncpy( ip, "???", sizeof(ip) );

        if( !bl && isLocal( ai->ai_addr ) )
        {
            if( loglevel >= 2 )
                sysprintLog( LOG_INFO, "Not blocking local IP %s.", ip );
            ai = ai->ai_next;
            continue;
        }

        rc = fw_add( ai->ai_addr, ai->ai_addrlen, value, table );

        if( rc == 2 )
        {
            // don't count existing IPs as errors
            if( loglevel >= 2 )
                sysprintLog( LOG_INFO, "IP %s already in IPFW table %d.", ip, table );
        }
        else if( rc )
        {
            if( loglevel >= 1 )
                sysprintLog( LOG_NOTICE, "Failed to add IP %s to IPFW table %d (rc=%d).", ip, table, rc );
            err--;
        }
        else
            if( loglevel >= 2 )
            {
                if( rt > 0 )
                    sysprintLog( LOG_INFO, "Added %s to IPFW table %i for %ld seconds.", ip, table, rt );
                else
                    sysprintLog( LOG_INFO, "Added %s to IPFW table %d.", ip, table );
            }

        ai = ai->ai_next;
    }

    freeaddrinfo( res );

    return err;
}

// Add the given host (DNS name or IP address) to firewall table
int addHost( const char* host, uint32_t value, uint32_t table )
{
    return addHostLong( host, value, table, 0, 0 );
}

// Log a message either to the console (if run interactively) or to syslog
void printLog( int priority, const char * restrict message, ...)
{
    va_list ap;
    va_start( ap, message );

    if( isatty( fileno( stderr ) ) )
        vfprintf( stderr, message, ap );
    else
        vsysprintLog( priority, message, ap );

    va_end( ap );
}