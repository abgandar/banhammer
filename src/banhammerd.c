/*
 Copyright 2007-2015 Alexander Wittig. All rights reserved.

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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <sysexits.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <pwd.h>
#include <libutil.h>
#include <getopt.h>
#include <err.h>

#include "banlib.h"

// entry type for tables we are watching
struct table {
    u_int16_t table;
    STAILQ_ENTRY(table) next;
};

// head of list of tables we are watching
STAILQ_HEAD( _tables, table ) tables = STAILQ_HEAD_INITIALIZER( tables );

// default configuration options
int loglevel = 2;
static int sleep_time = 60;
static char* state_file = NULL;
static char* pid_file = NULL;
static char* root_dir = NULL;
static int show_hostname = 1;

// signal handler variable
static int done = 0;

// state file handle
static FILE *sf = NULL;

// command line options and their aliases
static const struct option longopts[] = {
     { "table", required_argument, NULL, 't' },
     { "sleep", required_argument, NULL, 's' },
     { "pidfile", required_argument, NULL, 'p' },
     { "directory", required_argument, NULL, 'd' },
     { "statefile", required_argument, NULL, 'S' },
     { "foreground", no_argument, NULL, 'f' },
     { "cron", no_argument, NULL, 'C' },
     { "list", no_argument, NULL, 'L' },
     { "help", no_argument, NULL, 'h' },
     { "noresolve", no_argument, NULL, 'n' },
     { "quiet", no_argument, NULL, 'q' },
     { "verbose", no_argument, NULL, 'v' },
     { NULL, 0, NULL, 0 }
};


// show usage
static void usage( )
{
    errx( EX_USAGE,
          "\n"
          "Usage: banhammerd -h | -L [-n] -t tables | -C -t tables |\n"
          "                  -t tables [-s seconds] [-S statefile] [-p pidfile]\n"
          "                  [-d directory] [-f] [-n] [-v] [-q]\n"
          " --help, -h\tprint this message and exit\n"
          " --table, -t\tcomma separated list of IPFW table numbers to operate on\n"
          " --list, -L\tlist the currently blocked hosts and exit\n"
          " --cron, -C\tperform one cleaning cycle and exit (\"cron mode\")\n"
          " --sleep, -s\ttime in seconds between purging expired hosts (default: %d)\n"
          " --statefile, -S\tsave and restore state of IPFW tables in file \"statefile\"\n"
          " --pidfile, -p\tPID filename\n"
          " --directory, -d\tchroot to this directory before running\n"
          " --foreground, -f\trun in foreground (do not daemonize)\n"
          " --noresolve, -n\tDo not look up hostname of IP addresses when listing\n"
          " --verbose, -v\tincrease log level\n"
          " --quiet, -q\tdecrease log level\n"
          "\n", sleep_time );
}

// show address and associated timeout value
static void print_stat( struct sockaddr *addr, socklen_t addrlen, u_int32_t value, u_int16_t table )
{
    char hostname[NI_MAXHOST], ip[NI_MAXHOST];
    int days, hrs, min, sec;

    // calculate expiration time
    sec = value - time( NULL );
    if( sec >= 0 )
    {
        min = sec / 60;
        sec %= 60;
        hrs = min / 60;
        min %= 60;
        days = hrs / 24;
        hrs %= 24;
    }

    // pretty print address and host name
    if( getnameinfo( addr, addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST ) )
        strncpy( ip, "???", sizeof(ip) );
    if( !show_hostname || getnameinfo( addr, addrlen, hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD ) )
        strncpy( hostname, "---", sizeof(hostname) );

    if( value == 0 )
        printf( "%s\t   never\t\t%s\n", ip, hostname );
    else if( sec < 0 )
        printf( "%s\t  expired\t\t%s\n", ip, hostname );
    else
        printf( "%s\t%dd%dh%dm%ds\t%s\n", ip, days, hrs, min, sec, hostname );
}

// show all addresses and associated timeout values
static int show_stats( )
{
    int rc = 0;
    struct table *ptr;

    STAILQ_FOREACH( ptr, &tables, next )
    {
        printf( "ENTRIES IN IPFW TABLE %i\n"
               "=================================================\n"
               "IP address\texpires in\t\thost name\n", ptr->table );
        rc |= fw_list( print_stat, ptr->table );
        printf( "\n" );
    }

    if( rc )
        return EX_SOFTWARE;
    else
        return EXIT_SUCCESS;
}

// check if "addr" with its associated "value" has timed out and if so, remove it
static void check_entry( struct sockaddr *addr, socklen_t addrlen, u_int32_t value, u_int16_t table )
{
    char ip[NI_MAXHOST];

    if( (value != 0) && (time( NULL ) > value) )
    {
        // pretty print address if needed
        if( loglevel >= 1 )
            if( getnameinfo( addr, addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST ) )
                strncpy( ip, "???", sizeof(ip) );

        if( fw_del( addr, addrlen, table ) )
        {
            if( loglevel >= 1 )
                syslog( LOG_WARNING, "Error removing %s from IPFW table %i (%i)", ip, table, errno );
        }
        else
            if( loglevel >= 2 )
                syslog( LOG_INFO, "Removed %s from IPFW table %i", ip, table );
    }
}

// signal handler
static void handle_sigs( int signal )
{
    switch( signal )
    {
        case SIGINFO:
            show_stats( );
            break;

        default:
            // sleep( ) automatically is cancelled as soon as a signal arrives.
            // Therefore we only need to set done to 1.
            done = 1;
            break;
    }
}

// clean out IP table once
static int clean_once( )
{
    int rc = 0;
    struct table *ptr;

    STAILQ_FOREACH( ptr, &tables, next )
        rc |= fw_list( check_entry, ptr->table );

    return rc ? EX_SOFTWARE : EXIT_SUCCESS;
}

// write a table entry to state_file
static void save_entry( struct sockaddr *addr, socklen_t addrlen, u_int32_t value, u_int16_t table )
{
    char ip[NI_MAXHOST];

    if( !getnameinfo( addr, addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST ) )
        fprintf( sf, "%u\t%u\t%s\n", table, value, ip );
}

// save the state of all watched tables in state_file
static void save_state( )
{
    struct table *ptr;
    time_t ct = time( NULL );

    if( !state_file ) return;
    if( !(sf = fopen( state_file, "w" )) )
    {
        if( loglevel >= 1 )
            syslog( LOG_WARNING, "Could not open state file '%s' for writing.", state_file );
        return;
    }
    fprintf( sf, "# banhammerd IPFW table state %s# table\tvalue\tIP\n", ctime( &ct ) );

    STAILQ_FOREACH( ptr, &tables, next )
        fw_list( save_entry, ptr->table );

    fchmod( fileno( sf ), S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH );
    fchown( fileno( sf ), 0, -1 );
    fclose( sf );
}

// restore the state of all tables from state_file
static void load_state( )
{
    char *line = NULL, *ip, *p;
    size_t len = 0;
    ssize_t sl;
    int i = 0;
    uint32_t table, value;
    struct stat sb;

    if( !state_file ) return;

    // for safety reasons we only allow files owned by root and only writeable by root
    if( stat( state_file, &sb ) )
    {
        if( loglevel >= 2 )
            syslog( LOG_WARNING, "Could not examine state file '%s'.", state_file );
        return;
    }
    if( (sb.st_uid != 0) || (sb.st_mode&(S_IWGRP|S_IWOTH)) || !S_ISREG(sb.st_mode) )
    {
        if( loglevel >= 1 )
            syslog( LOG_ERR, "State file '%s' must be owned by root and be writeable only by owner.", state_file );
        return;
    }

    if( !(sf = fopen( state_file, "r" )) )
    {
        if( loglevel >= 2 )
            syslog( LOG_WARNING, "Could not open state file '%s' for reading.", state_file );
        return;
    }

    while( (sl = readline( &line, &len, sf )) != -1 )
    {
        i++;
        if( (sl == 0) || (*line == '#') ) continue;
        p = line;

        ip = strsep( &p, " \t" );
        if( !ip )
        {
            if( loglevel >= 2 )
                syslog( LOG_INFO, "Skipping invalid state file entry (%s:%d)", state_file, i );
            continue;
        }
        table = strtol( ip, &ip, 10 );
        if( *ip != '\0' )
        {
            if( loglevel >= 2 )
                syslog( LOG_INFO, "Skipping invalid state file entry (%s:%d)", state_file, i );
            continue;
        }

        ip = strsep( &p, " \t" );
        if( !ip )
        {
            if( loglevel >= 2 )
                syslog( LOG_INFO, "Skipping invalid state file entry (%s:%d)", state_file, i );
            continue;
        }
        value = strtol( ip, &ip, 10 );
        if( *ip != '\0' )
        {
            if( loglevel >= 1 )
                syslog( LOG_INFO, "Skipping invalid state file entry (%s:%d)", state_file, i );
            continue;
        }

        ip = strsep( &p, " \t" );
        if( !ip )
        {
            if( loglevel >= 1 )
                syslog( LOG_INFO, "Skipping invalid state file entry (%s:%d)", state_file, i );
            continue;
        }

        addHost( ip, value, table );
    }

    free( line );
    fclose( sf );
}

// enter the clean cycle and demonize depending on parameter
static int clean_cycle( int daemonize )
{
    struct pidfh *pfh = NULL;
    pid_t otherpid;

    // check PID file if we are already running and create our own
    if( pid_file )
    {
        pfh = pidfile_open( pid_file, 0600, &otherpid );
        if( pfh == NULL )
        {
            if( errno == EEXIST )
            {
                fw_close( );
                closelog( );
                errx( EXIT_FAILURE, "Another instance is already running (pid=%d).", otherpid );
            }
            warn( "Cannot open or create pid file: %s.", pid_file );
        }
    }

    // now that we have a PID file handle we can change root if necessary
    if( root_dir && chroot( root_dir ) )
        warn( "Changing root to %s failed.", root_dir );

    // daemonize if necessary and show error if that fails.
    if( daemonize && daemon( 0, 0 ) )
    {
        pidfile_remove( pfh );
        fw_close( );
        closelog( );
        errx( EX_OSERR, "Failed to become a daemon." );
    }

    // write current PID
    pidfile_write( pfh );

    // set up signal handlers
    signal( SIGTERM, handle_sigs );
    signal( SIGINT, handle_sigs );
    signal( SIGINFO, handle_sigs );
    signal( SIGPIPE, SIG_IGN );

    // load state
    load_state( );

    // the main loop
    while( !done )
    {
        clean_once( );
        sleep( sleep_time );
    }

    // clean up
    save_state( );
    if( pfh ) pidfile_remove( pfh );

    return EXIT_SUCCESS;
}

// the main program with the main loop
int main( int argc, char *argv[] )
{
    char ch, *c;
    int rc, i, mode = 1;
    struct table* nptr;

    STAILQ_INIT( &tables );

    // see if we are root
    if( geteuid( ) != 0 )
        errx( EX_OSERR, "Must be run as root." );

    while( (ch = getopt_long( argc, argv, "t:S:R:p:d:s:hfnvqLC", longopts, NULL )) != -1 )
    {
        switch( ch )
        {
            case 't':
                // get all numbers separated by commas
                while( (c = strsep( &optarg, "," )) )
                {
                    i = strtol( c, NULL, 10 );
                    if( i > 0 )
                    {
                        nptr = (struct table*) malloc( sizeof(struct table) );
                        if( !nptr )
                            errx( EX_OSERR, "Could not allocate memory." );
                        nptr->table = i;
                        STAILQ_INSERT_TAIL( &tables, nptr, next );
                    }
                    else
                        errx( EX_USAGE, "Table argument must be a comma separated list of positive numbers." );
                }
                break;

            case 's':
                sleep_time = strtol( optarg, NULL, 10 );
                if( sleep_time < 1 )
                    errx( EX_USAGE, "Time to sleep must be at least 1 second." );
                break;

            case 'f':
                if( mode != 1 )
                    errx( EX_USAGE, "Options -C, -f and -L are mutually exclusive. Please only specify one of them." );
                mode = 0;
                break;

            case 'C':
                if( mode != 1 )
                    errx( EX_USAGE, "Options -C, -f and -L are mutually exclusive. Please only specify one of them." );
                mode = 2;
                break;

            case 'L':
                if( mode != 1 )
                    errx( EX_USAGE, "Options -C, -f and -L are mutually exclusive. Please only specify one of them." );
                mode = 3;
                break;

            case 'S':
                state_file = optarg;
                break;

            case 'n':
                show_hostname = 0;
                break;

            case 'p':
                pid_file = optarg;
                break;

            case 'd':
                root_dir = optarg;
                break;

            case 'v':
                loglevel++;
                break;

            case 'q':
                loglevel--;
                break;

            case 'h':
            default:
                usage( );
                break;
        }
    }

    // check if we were given enough tables
    if( STAILQ_EMPTY( &tables ) )
        errx( EX_USAGE, "You must specify at least one IPFW table to operate on." );

    // initialize firewall
    rc = fw_init( );
    if( rc )
        errx( EX_CONFIG, "Error initializing IPFW (rc=%d).", rc );

    // open syslog
    openlog( "banhammerd", LOG_PID, LOG_SECURITY );

    // run the requested mode
    switch( mode )
    {
        case 0:
        case 1:
            rc = clean_cycle( mode );
            break;
        case 2:
            rc = clean_once( );
            break;
        case 3:
            rc = show_stats( );
            break;
    }

    // clean up
    fw_close( );
    closelog( );

    while( !STAILQ_EMPTY( &tables ) )
    {
        nptr = STAILQ_FIRST( &tables );
        STAILQ_REMOVE_HEAD( &tables, next );
        free( nptr );
    }

    return rc;
}
