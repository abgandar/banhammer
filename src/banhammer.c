/*
 Copyright 2007-2025 Alexander Wittig. All rights reserved.

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
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <getopt.h>
#ifdef WITH_USERS
#include <pwd.h>
#include <grp.h>
#endif

#ifdef HAVE_LIBPCRE2
    #define PCRE2_CODE_UNIT_WIDTH 8
    #include <pcre2.h>
#else
    #include <regex.h>
#endif

#include "banlib.h"

// flags for group
const unsigned char BIF_CONTINUE   = 0x01;    // continue processing after hit
const unsigned char BIF_SKIP       = 0x02;    // skip to next group after hit
const unsigned char BIF_WARNFAIL   = 0x04;    // warn on hits after blocking
const unsigned char BIF_BLOCKFAIL  = 0x08;    // keep blocking on hits after blocking
const unsigned char BIF_WARNMAX    = 0x10;    // warn if maxblock is exceeded
const unsigned char BIF_BLOCKMAX   = 0x20;    // block hosts if maxblock is reached
const unsigned char BIF_BLOCKLOCAL = 0x40;    // block hosts if maxblock is reached

// error numbers
const unsigned int ERR_NO_ERROR       = 0;
const unsigned int ERR_INVALID_GROUP  = 1;
const unsigned int ERR_INVALID_KEY    = 2;
const unsigned int ERR_INVALID_VALUE  = 3;
const unsigned int ERR_INVALID_REGEXP = 4;
const unsigned int ERR_OUT_OF_MEMORY  = 5;

// error messages
const char* error_messages[] = {
    "No error",
    "Invalid group line (missing [ ])",
    "Invalid group line (invalid key)",
    "Invalid group line (invalid value)",
#ifdef HAVE_LIBPCRE2
    "Invalid regular expression or no matches defined",
#else
    "Invalid regular expression or no matches defined (maybe not a POSIX regex?)",
#endif
    "Memory allocation failed"
};


// linked list of hosts for watch list
struct host {
    unsigned int count;         // Number of hits
    time_t access_time;         // Time of first access
    char* hostname;             // Name of the host (as matched by the regexp pattern)
    STAILQ_ENTRY(host) next;    // Singly linked list entry
};

STAILQ_HEAD( _hosts, host );

// linked list of the regexps
struct regexp {
#ifdef HAVE_LIBPCRE2
    pcre2_code* re;             // Compiled pattern
#else
    regex_t re;                 // Compiled pattern
#endif
    char* exp;                  // Original pattern
    unsigned int matches;       // Statistics how often that pattern matched
    STAILQ_ENTRY(regexp) next;  // Singly linked list entry
};

STAILQ_HEAD( _regexps, regexp );

// linked list of blocking groups from the configuration file
struct bgroup {
    unsigned int max_count;         // Number of hits before blocking
    time_t within_time;             // Time within which access has to happen
    time_t reset_time;              // Time to block IP for
    unsigned int table;             // IPFW table to add IP to
    unsigned int max_hosts;         // Maximum number of hosts allowed in watchlist
    unsigned int random;            // Maximum randomization of blocking time
    unsigned char flags;            // Flags for this group
    unsigned int reg_count;         // Number of regex pattern
    unsigned int host_count;        // Number of hosts in watch list
    struct _hosts hosts;            // Host watch list
    struct _regexps regexps;        // Regular expression list
    STAILQ_ENTRY(bgroup) next;       // Singly linked list entry
};

// Single global head of the list of groups this program is operating on
STAILQ_HEAD( _groups, bgroup ) groups;

// global configuration options and their default
int loglevel = 2;
static char* root_dir = NULL;
#ifdef WITH_USERS
static char* uid_name = NULL;
static char* gid_name = NULL;
static uid_t uid = 0;
static gid_t gid = 0;
#endif
static const char* default_config_file = SYSCONFDIR "/banhammer.conf";
static const struct bgroup default_group = { 4, 60, 600, 1, 0, 30, 0x08|0x10|0x20, 0, 0, { 0 }, { 0 } };
// 4 hits within 60 seconds, block for 10 min in table 1, no watchlist limit, randomize time +-30%, warn if blocking failed and warn and block if maxhost exceeded, 0 references, 0 hosts on watch, and two empty lists

// command line options and their aliases
static const struct option longopts[] = {
     { "directory", required_argument, NULL, 'd' },
     { "file", required_argument, NULL, 'f' },
#ifdef WITH_USERS
     { "group", required_argument, NULL, 'g' },
     { "user", required_argument, NULL, 'u' },
#endif
     { "check", no_argument, NULL, 'c' },
     { "help", no_argument, NULL, 'h' },
     { "quiet", no_argument, NULL, 'q' },
     { "version", no_argument, NULL, 'v' },
     { "verbose", no_argument, NULL, 'V' },
     { NULL, 0, NULL, 0 }
};

#ifndef HAVE_LIBPCRE2
// Extract a match from regexp result
static int regex_get_substring( const char* line, regmatch_t* pmatch, char** hostname )
{
    // there is no match (both are -1) or it is empty (both equal)
    if( pmatch->rm_so >= pmatch->rm_eo )
        return 0;

    *hostname = (char*) calloc( pmatch->rm_eo - pmatch->rm_so + 1, sizeof(char) );
    if( !*hostname )
        return 0;

    strncpy( *hostname, &line[pmatch->rm_so], pmatch->rm_eo - pmatch->rm_so );
    (*hostname)[pmatch->rm_eo - pmatch->rm_so] = '\0';

    return 1;
}
#endif

// Show help
static void usage( )
{
    fprintf( stderr,
#ifdef WITH_USERS
          "Usage: banhammer -h | -v | [-c] [-V] [-q] [-d dir] [-u user] [-g group] -f config_file [-f ...]\n"
#else
          "Usage: banhammer -h | -v | [-c] [-V] [-q] [-d dir] -f config_file [-f ...]\n"
#endif
          " --help, -h\n\t\tprint this message and exit\n"
          " --version, -v\n\t\tprint version and build information\n"
          " --check, -c\n\t\tcheck configuration for errors and exit\n"
          " --verbose, -V\n\t\tincrease logging level (repeat for more)\n"
          " --quiet, -q\n\t\tdecrease logging level (repeat for less)\n"
          " --directory, -d\n"
          "\t\tchroot to this directory (default: none)\n"
#ifdef WITH_USERS
          " --user, -u\n\t\tdrop priviliges to run as this user\n"
          " --group, -g\n\t\tdrop priviliges to run as this group\n"
#endif
          " --file, -f\n\t\tconfiguration file with pattern to match against\n"
          "\t\t(default if none specified: %s)\n"
          "\nFor more details see banhammer(1).\n",
          default_config_file );
}

// Show version information
static void version( )
{
    fprintf( stderr, PACKAGE_STRING "\n\n" );
#ifdef HAVE_LIBPCRE2
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
    char ver[64];
    pcre2_config( PCRE2_CONFIG_VERSION, ver );
    fprintf( stderr,
        "Built with PCRE regular expressions.\n"
        "\tCompiled with PCRE version:\t%i.%i %s\n"
        "\tLinked with PCRE version:\t%s\n",
        PCRE2_MAJOR, PCRE2_MINOR, STRINGIFY(PCRE2_DATE), ver );
#else
    fprintf( stderr, "Built with POSIX regular expressions.\n" );
#endif
#ifdef WITH_IPV6
    fprintf( stderr, "Built with IPv6 support via IPFW 3.\n" );
#else
    fprintf( stderr, "Built with IPv4 support only via IPFW 2.\n" );
#endif
#ifdef WITH_USERS
    fprintf( stderr, "Built with support to drop priviliges.\n" );
#endif
    fprintf( stderr,
        "\n"
        "Default config file: %s\n"
        "Default chroot dir:  %s\n"
        "Default logging level:  %d\n"
        "Default blocking settings:\n"
        "\ttable = %d\n"
        "\tcount = %d\n"
        "\twithin = %ld seconds\n"
        "\treset = %ld seconds\n"
        "\trandom = %d %%\n"
        "\tonfail = %s\n"
        "\twarnfail = %s\n"
        "\tcontinue = %s\n"
        "\tmaxhosts = %d\n"
        "\tonmax = %s\n"
        "\twarnmax = %s\n"
        "\tblocklocal = %s\n",
        default_config_file ? default_config_file : "(none)",
        root_dir ? root_dir : "(none)",
        loglevel,
        default_group.table, default_group.max_count, default_group.within_time,
        default_group.reset_time, default_group.random,
        (default_group.flags & BIF_BLOCKFAIL) ? "block" : "ignore",
        (default_group.flags & BIF_WARNFAIL) ? "yes" : "no",
        (default_group.flags & BIF_CONTINUE) ?
            ((default_group.flags & BIF_SKIP) ? "next" : "yes") : "no",
        default_group.max_hosts,
        (default_group.flags & BIF_BLOCKMAX) ? "block" : "ignore",
        (default_group.flags & BIF_WARNMAX) ? "yes" : "no",
        (default_group.flags & BIF_BLOCKLOCAL) ? "yes" : "no"
    );
}

// Log a message either to the console (if run interactively) or to syslog
static void log( int priority, const char * restrict message, ...)
{
    va_list ap;
    va_start( ap, message );

    if( isatty( fileno( stderr ) ) )
        vfprintf( stderr, message, ap );
    else
        vsyslog( priority, message, ap );

    va_end( ap );
}

// Walk the groups host list and delete old entries on the way. If we find the
// given host name: bump it up and if necessary block it. If we don't find it,
// add it.
static int checkHost( const char *host, struct bgroup* g )
{
    time_t ct = time( NULL ), rt = g->reset_time, bt = 0;
    struct host *ptr;

    // clean expired hosts from the beginning of the watch list (always ordered by access time)
    while( !STAILQ_EMPTY( &g->hosts ) )
    {
        ptr = STAILQ_FIRST( &g->hosts );
        if( ptr->access_time + g->within_time < ct )
        {
            if( loglevel >= 3 )
               log( LOG_DEBUG, "Removed host '%s' from watch list", ptr->hostname );

            // Remove and free this entry
            STAILQ_REMOVE_HEAD( &g->hosts, next );
            g->host_count--;
            free( ptr->hostname );
            free( ptr );
        }
        else
            // From here on out all entries are legitimate, stop searching
            break;
    }

    // randomize reset time if needed
    if( rt > 0 )
    {
        rt += (((random( )&0xFFFF)-0x8000)*g->random*rt)/(100*0xFFFF);
        bt = ct+rt;
    }

    // check if the host matches one already on the watch list
    STAILQ_FOREACH( ptr, &g->hosts, next )
        if( strcmp( host, ptr->hostname ) == 0 )
        {
            ptr->count++;
            if( loglevel >= 3 )
               log( LOG_DEBUG, "Increased hit count for host '%s' to %i.", host, ptr->count );

            if( ptr->count == g->max_count )
                addHostLong( host, bt, g->table, rt, g->flags & BIF_BLOCKLOCAL );
            else if( ptr->count > g->max_count )
            {
                if( (loglevel >= 1) && (g->flags & BIF_WARNFAIL) && (ptr->count == g->max_count + 1) )
                    log( LOG_WARNING, "Hit from blocked host '%s'.", host );
                if( g->flags & BIF_BLOCKFAIL )
                    addHostLong( host, bt, g->table, rt, g->flags & BIF_BLOCKLOCAL );
            }
            return 1;
        }

    // We are through and nothing was found. Check if max number of hosts has been reached
    if( (g->max_hosts > 0) && (g->host_count >= g->max_hosts) )
    {
        if( (loglevel >= 1) && (g->flags & BIF_WARNMAX) )
            log( LOG_NOTICE, "Maximum number of watched hosts exceeded." );

        // block the host preemptively if requested
        if( g->flags & BIF_BLOCKMAX )
        {
            if( loglevel >= 2 )
                log( LOG_NOTICE, "Preemptively blocking host '%s'.", host );
            addHostLong( host, bt, g->table, rt, g->flags & BIF_BLOCKLOCAL );
        }
        else
            if( loglevel >= 2 )
                log( LOG_NOTICE, "Ignoring host '%s'.", host );
    }
    else
    {
        if( (ptr = (struct host*) malloc( sizeof(struct host) )) == NULL )
        {
            if( loglevel >= 1 )
                log( LOG_ERR, "Out of memory, ignoring host '%s'.", host );
            return -1;
        }

        g->host_count++;
        ptr->count = 1;
        ptr->access_time = ct;
        ptr->hostname = strdup( host );

        STAILQ_INSERT_TAIL( &g->hosts, ptr, next );

        if( loglevel >= 3 )
            log( LOG_DEBUG, "Added host '%s' to watch list.", host );

        // just checking if someone is really cruel
        if( ptr->count == g->max_count )
            addHostLong( host, bt, g->table, rt, g->flags & BIF_BLOCKLOCAL );
    }

    return 0;
}

// print diagnostics and statistics about the current status of the program
void printTable( )
{
    struct host *h;
    struct regexp *r;
    struct bgroup *g;
    int now = time( NULL );

    STAILQ_FOREACH( g, &groups, next )
    {
        log( LOG_NOTICE, "[table=%d, within=%ld, count=%d, reset=%ld, random=%d, continue=%s,\n"
                        " warnfail=%s, onfail=%s, maxhosts=%d, warnmax=%s, onmax=%s, blocklocal=%s]\n",
                        g->table,
                        g->within_time,
                        g->max_count,
                        g->reset_time,
                        g->random,
                        g->flags & BIF_CONTINUE ? (g->flags & BIF_SKIP ? "next" : "yes") : "no",
                        g->flags & BIF_WARNFAIL ? "yes" : "no",
                        g->flags & BIF_BLOCKFAIL ? "block" : "ignore",
                        g->max_hosts,
                        g->flags & BIF_WARNMAX ? "yes" : "no",
                        g->flags & BIF_BLOCKMAX ? "block" : "ignore",
                        g->flags & BIF_BLOCKLOCAL ? "yes" : "no" );
        log( LOG_NOTICE, "Number of pattern: %d\t\tCurrently watched hosts: %d\n", g->reg_count, g->host_count );

        log( LOG_NOTICE, "\nmatches\t\tpattern\n"
                        "-----------------------------------------------------------\n" );
        STAILQ_FOREACH( r, &g->regexps, next )
            log( LOG_NOTICE, "%d\t\t%s\n", r->matches, r->exp );

        log( LOG_NOTICE, "\nhost\t\t\tcount\texpires in\tstatus\n"
                        "-----------------------------------------------------------\n" );
        STAILQ_FOREACH( h, &g->hosts, next )
            log( LOG_NOTICE, "%s\t\t\t%d\t%ld sec\t\t%s\n", h->hostname, h->count, h->access_time + g->within_time - now,
                            h->count > g->max_count ? "failed" : (h->count == g->max_count ? "blocked" : "watching") );

        log( LOG_NOTICE, "\n\n" );
    }
}

// handles signals
void signalHandler( int sig )
{
    switch( sig )
    {
        case SIGINFO:
            printTable( );
            break;

        case SIGHUP:
            // do nothing
            // fgetln(...) in the main loop returns automatically because we set siginterrupt for SIGHUP
            break;

        default:
            // close stdin so that fgetln(...) in the main loop returns and never succeeds again
            fclose( stdin );
            break;
    }
}

// Add a regular expression to the group g
int addRegexp( char* exp, struct bgroup* g )
{
#ifdef HAVE_LIBPCRE2
    int error;
    PCRE2_SIZE offset;
#endif
    int i;
    struct regexp* nptr;

    // check for minimum regexp length
    i = strlen( exp );
    if( i < 1 ) return ERR_INVALID_REGEXP;

    nptr = (struct regexp*) malloc( sizeof(struct regexp) );
    if( !nptr )
        err( EX_OSERR, "%s", error_messages[ERR_OUT_OF_MEMORY] );

#ifdef HAVE_LIBPCRE2
    nptr->re = pcre2_compile( (PCRE2_SPTR)exp, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS, &error, &offset, NULL );
    if( !nptr->re )
    {
        free( nptr );
        return ERR_INVALID_REGEXP;
    }

    // check to see if the RE has at least one match
    if( pcre2_pattern_info( nptr->re, PCRE2_INFO_CAPTURECOUNT, &i ) || (i < 1) )
    {
        pcre2_code_free( nptr->re );
        free( nptr );
        return ERR_INVALID_REGEXP;
    }
#else
    if( regcomp( &nptr->re, exp, REG_EXTENDED | REG_NEWLINE | REG_ICASE ) )
    {
        free( nptr );
        return ERR_INVALID_REGEXP;
    }

    // check to see if the RE has at least one match
    if( nptr->re.re_nsub < 1 )
    {
        regfree( &nptr->re );
        free( nptr );
        return ERR_INVALID_REGEXP;
    }
#endif

    nptr->matches = 0;
    nptr->exp = strdup( exp );

    // Add to regexp list
    STAILQ_INSERT_TAIL( &g->regexps, nptr, next );
    g->reg_count++;

    return 0;
}

// Parse a group definition line into the newly allocated pg
// XXX: change to be more lenient and only warn on errors.
int parseGroupData( char* line, struct bgroup** pg )
{
    int i;
    char *value, *key, *c;
    struct bgroup g = default_group;    // temporary group

    *pg = NULL;

    // check for [] and remove them
    i = strlen( line )-1;
    if( (i < 1) || (*line != '[') || (line[i] != ']') )
        return ERR_INVALID_GROUP;
    line[i] = '\0';
    line++;

    // chop up into comma separated values
    while( line )
    {
        // get key/value pair
        value = strsep( &line, "," );
        key = strsep( &value, "=" );

        // skip white space around key
        for( ; (*key != '\0') && strchr( " \t\n\r", *key ); key++ )
            ;
        for( c=key; *c != '\0'; c++ )
            ;
        c--;
        for( ; (key <= c) && strchr( " \t\n\r", *c ); c-- )
            ;
        c++;
        *c = '\0';

        // skip white space around value
        if( value )
        {
            for( ; (*value != '\0') && strchr( " \t\n\r", *value ); value++ )
                ;
            for( c=value; *c != '\0'; c++ )
                ;
            c--;
            for( ; (value <= c) && strchr( " \t\n\r", *c ); c-- )
                ;
            c++;
            *c = '\0';
        }

        // check for keys with optional arguments
        if( strcasecmp( key, "continue" ) == 0 )
        {
            if( !value || (strcasecmp( value, "yes" ) == 0) )
            {
                g.flags |= BIF_CONTINUE;
                g.flags &= ~BIF_SKIP;
            }
            else if( strcasecmp( value, "no" ) == 0 )
                g.flags &= ~BIF_CONTINUE;
            else if( (strcasecmp( value, "next" ) == 0) || (strcasecmp( value, "nextblock" ) == 0) || (strcasecmp( value, "skip" ) == 0) )
                g.flags |= BIF_CONTINUE|BIF_SKIP;
            else
                return ERR_INVALID_VALUE;
        }
        else if( strcasecmp( key, "warnfail" ) == 0 )
        {
            if( !value || (strcasecmp( value, "yes" ) == 0) )
                g.flags |= BIF_WARNFAIL;
            else if( strcasecmp( value, "no" ) == 0 )
                g.flags &= ~BIF_WARNFAIL;
            else
                return ERR_INVALID_VALUE;
        }
        else if( strcasecmp( key, "onfail" ) == 0 )
        {
            if( !value )
                return ERR_INVALID_VALUE;
            else if( strcasecmp( value, "block" ) == 0 )
                g.flags |= BIF_BLOCKFAIL;
            else if( (strcasecmp( value, "none" ) == 0) || (strcasecmp( value, "ignore" ) == 0) )
                g.flags &= ~BIF_BLOCKFAIL;
            else
                return ERR_INVALID_VALUE;
        }
        else if( strcasecmp( key, "warnmax" ) == 0 )
        {
            if( !value || (strcasecmp( value, "yes" ) == 0) )
                g.flags |= BIF_WARNMAX;
            else if( strcasecmp( value, "no" ) == 0 )
                g.flags &= ~BIF_WARNMAX;
            else
                return ERR_INVALID_VALUE;
        }
        else if( strcasecmp( key, "onmax" ) == 0 )
        {
            if( !value )
                return ERR_INVALID_VALUE;
            else if( strcasecmp( value, "block" ) == 0 )
                g.flags |= BIF_BLOCKMAX;
            else if( (strcasecmp( value, "none" ) == 0) || (strcasecmp( value, "ignore" ) == 0) )
                g.flags &= ~BIF_BLOCKMAX;
            else
                return ERR_INVALID_VALUE;
        }
        else if( strcasecmp( key, "blocklocal" ) == 0 )
        {
            if( !value || (strcasecmp( value, "yes" ) == 0) )
                g.flags |= BIF_BLOCKLOCAL;
            else if( strcasecmp( value, "no" ) == 0 )
                g.flags &= ~BIF_BLOCKLOCAL;
            else
                return ERR_INVALID_VALUE;
        }
        else if( (strcasecmp( key, "random" ) == 0) || (strcasecmp( key, "randomize" ) == 0) )
        {
            if( !value )
                return ERR_INVALID_VALUE;
            else if( strcasecmp( value, "no" ) == 0 )
                g.random = 0;
            else
            {
                // convert value to number
                i = strtol( value, &value, 10 );
                if( (*value != '\0') || abs(i) > 100 ) return ERR_INVALID_VALUE;
                g.random = i;
            }
        }
        else if( strcasecmp( key, "maxhosts" ) == 0 )
        {
            if( !value )
                return ERR_INVALID_VALUE;
            else
            {
                // convert value to number
                i = strtol( value, &value, 10 );
                if( (*value != '\0') || i <= 0 ) return ERR_INVALID_VALUE;
                g.max_hosts = i;
            }
        }
        else if( strcasecmp( key, "count" ) == 0 )
        {
            if( !value )
                return ERR_INVALID_VALUE;
            else
            {
                // convert value to number
                i = strtol( value, &value, 10 );
                if( (*value != '\0') || i < 0 ) return ERR_INVALID_VALUE;
                g.max_count = i;
            }
        }
        else if( strcasecmp( key, "within" ) == 0 )
        {
            if( !value )
                return ERR_INVALID_VALUE;
            else
            {
                // convert value to number
                i = strtol( value, &value, 10 );
                if( (*value != '\0') || i < 0 ) return ERR_INVALID_VALUE;
                g.within_time = i;
            }
        }
        else if( strcasecmp( key, "reset" ) == 0 )
        {
            if( !value )
                return ERR_INVALID_VALUE;
            else
            {
                // convert value to number
                i = strtol( value, &value, 10 );
                if( (*value != '\0') || i < 0 ) return ERR_INVALID_VALUE;
                g.reset_time = i;
            }
        }
        else if( strcasecmp( key, "table" ) == 0 )
        {
            if( !value )
                return ERR_INVALID_VALUE;
            else
            {
                // convert value to number
                i = strtol( value, &value, 10 );
                if( (*value != '\0') || i < 0 ) return ERR_INVALID_VALUE;
                g.table = i;
            }
        }
        else if( *key != '\0' )                  // empty keys are no error
            return ERR_INVALID_KEY;
    }

    // allocate new group and copy temporary one
    if( !(*pg = (struct bgroup*) malloc( sizeof(struct bgroup) )) )
        err( EX_OSERR, "%s", error_messages[ERR_OUT_OF_MEMORY] );
    **pg = g;
    STAILQ_INIT( &(*pg)->hosts );
    STAILQ_INIT( &(*pg)->regexps );

    return 0;
}

// Add groups from a file to the global group table
int readConfigFile( const char* file )
{
    FILE* f;
    char* line = NULL;
    size_t size = 0;
    ssize_t len;
    int rc, ec = 0;
    struct bgroup* g;
    unsigned int lc = 0;

    f = fopen( file, "r" );
    if( !f )
    {
        warn( "Cannot open configuration file '%s'", file );
        return -1;
    }

    // read in all groups from the file
    while( readline( &line, &size, f ) != -1 )
    {
        lc++;
        if( (*line == '\0') || (*line == '#') ) continue;    // skip blank lines & comments

        // try to parse current line as group definition
        if( (rc = parseGroupData( line, &g )) )
        {
            warnx( "%s:%i  %s", file, lc, error_messages[rc] );
            ec++;
        }

        // read in regexps for this group until we hit a blank line
        while( readline( &line, &size, f ) > 0 )
        {
            lc++;
            if( *line == '#' ) continue;                     // skip comments

            if( g && (rc = addRegexp( line, g )) )
            {
                warnx( "%s:%i  %s", file, lc, error_messages[rc] );
                ec++;
            }
        }
        lc++;    // count the enpty line

        // if a block was read, add it block to the global groups table or free it
        if( g )
        {
            if( g->reg_count > 0 )
                STAILQ_INSERT_TAIL( &groups, g, next );
            else
                free( g );
        }
    }

    // clean up
    fclose( f );
    free( line );

    return ec;
}

// The main program loop
int mainLoop( int argc, char *argv[] )
{
    char *line = NULL, ch;
    int rc, i, done = 0;
    size_t length;
#ifdef WITH_USERS
    struct passwd *pwd;
    struct group *grp;
#endif
    int nmatch = 0;
    char *hostname;
#ifdef HAVE_LIBPCRE2
    pcre2_match_data *md;
    PCRE2_SIZE hostlen;
#else
    regmatch_t *pmatch;
#endif
    struct host *hptr;
    struct regexp *rptr;
    struct bgroup *gptr;

    STAILQ_INIT( &groups );

    // process command line
    while( (ch = getopt_long( argc, argv, "d:f:chqvV", longopts, NULL )) != -1 )
        switch( ch ) {
            case 'c':
                // in check mode, we don't enter main loop by closing stdin
                fclose( stdin );
                break;

            case 'd':
                root_dir = optarg;
                break;

            case 'f':
                if( readConfigFile( optarg ) )
                {
                    log( LOG_ALERT, "Invalid configuration in file '%s'.", optarg );
                    warnx( "Invalid configuration in file '%s'.", optarg );
                    return( EX_CONFIG );
                }
                done = 1;
                break;

#ifdef WITH_USERS
            case 'u':
                uid_name = optarg;
                pwd = getpwnam( uid_name );
                if( !pwd )
                {
                    log( LOG_ALERT, "Unknown user name '%s'.", optarg );
                    warnx( "Unknown user name '%s'.", optarg );
                    return( EX_CONFIG );
                }
                uid = pwd->pw_uid;
                break;

            case 'g':
                gid_name = optarg;
                grp = getgrnam( gid_name );
                if( !grp )
                {
                    log( LOG_ALERT, "Unknown group name '%s'.", optarg );
                    warnx( "Unknown group name '%s'.", optarg );
                    return( EX_CONFIG );
                }
                gid = grp->gr_gid;
                break;
 #endif

            case 'v':
                version( );
                return( EX_USAGE );

            case 'q':
                loglevel--;
                break;

            case 'V':
                loglevel++;
                break;

            case 'h':
            default:
                usage( );
                return( EX_USAGE );
        }

    // warn if there are extra options at the end
    if( optind < argc )
    {
        log( LOG_ALERT, "Invalid command line option '%s'.", argv[optind] );
        warnx( "Invalid command line option '%s'", argv[optind] );
        return( EX_CONFIG );
    }

    // read default config if none was specified on the command line
    if( !done )
        if( readConfigFile( default_config_file ) )
        {
            log( LOG_ALERT, "Invalid configuration in file '%s'.", default_config_file );
            warnx( "Invalid configuration in file '%s'", default_config_file );
            return( EX_CONFIG );
        }

    // check that we have at least one regexp
    i = 0;
    STAILQ_FOREACH( gptr, &groups, next )
        if( !STAILQ_EMPTY( &gptr->regexps ) ) i++;
    if( i == 0 )
    {
        log( LOG_ALERT, "No regular expression pattern specified for matching!" );
        warnx( "No regular expression pattern specified for matching" );
        return( EX_CONFIG );
    }

    // chroot to safe directory
    // from now on we don't do file I/O any more (except if we receive a SIGHUP, which is not supported in chroot mode)
    if( root_dir )
        if( chroot( root_dir ) )
            warn( "Changing root to %s failed", root_dir );

#ifdef WITH_USERS
    // drop root group
    if( gid )
    {
        rc = setgroups( 1, &gid );
        if( setgid( gid ) || rc )
            warn( "Changing group to %s (%d) failed", gid_name, gid );
    }

    // drop root user
    if( uid )
    {
        if( setuid( uid ) )
            warn( "Changing user to %s (%d) failed", uid_name, uid );
    }
 #endif

    // Update the list of local network interfaces at this point
    updateLocalInterfaces( );

    // find largest number of matching pattern and allocate ovector/pmatch accordingly
    STAILQ_FOREACH( gptr, &groups, next )
        STAILQ_FOREACH( rptr, &gptr->regexps, next )
        {
#ifdef HAVE_LIBPCRE2
            rc = pcre2_pattern_info( rptr->re, PCRE2_INFO_CAPTURECOUNT, &i );
            if( rc < 0 )
            {
                log( LOG_ERR, "Error getting number of PCRE2 regexp subpattern for '%s' (rc=%d).", rptr->exp, rc );
                warnx( "Error getting number of PCRE2 regexp subpattern for '%s' (rc=%d)", rptr->exp, rc );
                return( EX_SOFTWARE );
            }
            if( i > nmatch )
                nmatch = i;
#else
            if( rptr->re.re_nsub > nmatch )
                nmatch = rptr->re.re_nsub;
#endif
        }

    nmatch++;
#ifdef HAVE_LIBPCRE2
    md = pcre2_match_data_create( nmatch, NULL );
    if( !md )
    {
        log( LOG_ERR, "Error allocating enough memory for match_data (%u matches).", nmatch );
        warn( "Error allocating enough memory for match_data (%u matches)", nmatch );
        return( EX_OSERR );
    }
#else
    pmatch = (regmatch_t*) calloc( nmatch, sizeof(regmatch_t) );
    if( !pmatch )
    {
        log( LOG_ERR, "Error allocating enough memory for pmatch (%lud bytes).", nmatch*sizeof(regmatch_t) );
        warn( "Error allocating enough memory for pmatch (%lud bytes)", nmatch*sizeof(regmatch_t) );
        return( EX_OSERR );
    }
#endif

    // main loop
    while( (line = fgetln( stdin, &length )) )
    {
        // check all groups agains this string
        STAILQ_FOREACH( gptr, &groups, next )
        {
            done = 0;
            STAILQ_FOREACH( rptr, &gptr->regexps, next )
            {
#ifdef HAVE_LIBPCRE2
                rc = pcre2_match( rptr->re, (PCRE2_SPTR)line, length, 0, PCRE2_NOTEMPTY, md, NULL );

                if( rc <= 0 )
                {
                    if( rc != PCRE2_ERROR_NOMATCH )
                        log( LOG_ERR, "Error in pcre2_match for regexp '%s' with subject '%s' (rc=%d).", rptr->exp, line, rc );
                }
                else if( (pcre2_substring_get_byname( md, (PCRE2_SPTR)"host", (PCRE2_UCHAR**)&hostname, &hostlen ) == 0) ||
                         (pcre2_substring_get_bynumber( md, 1, (PCRE2_UCHAR**)&hostname, &hostlen ) == 0) )
                {
                    // we caught a bad guy!
                    if( loglevel >= 3 )
                        log( LOG_DEBUG, "Regular expression '%s' matches '%s' for host '%s'.", rptr->exp, line, hostname );
                    rptr->matches++;
                    checkHost( hostname, gptr );
                    pcre2_substring_free( (PCRE2_UCHAR*)hostname );
                    // proceed according to settings
                    if( !(gptr->flags & BIF_CONTINUE) )
                        done = 1;
                    else if( gptr->flags & BIF_SKIP )
                        break;
                }
                else
                    if( loglevel >= 1 )
                        log( LOG_NOTICE, "No substrings in matching regexp '%s' with subject '%s' (rc=%d).", rptr->exp, line, rc );
#else
                pmatch[0].rm_so = 0;
                pmatch[0].rm_eo = length;
                rc = regexec( &rptr->re, line, nmatch, pmatch, REG_STARTEND );

                if( rc )
                {
                    if( rc != REG_NOMATCH )
                        log( LOG_ERR, "Error in regexec for regexp '%s' with subject '%s' (rc=%d).", rptr->exp, line, rc );
                }
                else if( regex_get_substring( line, &pmatch[1], &hostname ) )
                {
                    // we caught a bad guy!
                    if( loglevel >= 3 )
                        log( LOG_DEBUG, "Regular expression '%s' matches '%s' for host '%s'.", rptr->exp, line, hostname );
                    rptr->matches++;
                    checkHost( hostname, gptr );
                    free( hostname );
                    // proceed according to settings
                    if( !(gptr->flags & BIF_CONTINUE) )
                        done = 1;
                    else if( gptr->flags & BIF_SKIP )
                        break;
                }
                else
                    if( loglevel >= 1 )
                        log( LOG_NOTICE, "No substrings in matching regexp '%s' with subject '%s' (rc=%d).", rptr->exp, line, rc );
#endif
            }
            if( done ) break;
        }
    }

    // save the return code in case we were interrupted (e.g. by SIGHUP)
    rc = errno;

#ifdef HAVE_LIBPCRE2
    pcre2_match_data_free( md );
#else
    free( pmatch );
#endif

    while( !STAILQ_EMPTY( &groups ) )
    {
        gptr = STAILQ_FIRST( &groups );
        STAILQ_REMOVE_HEAD( &groups, next );
        while( !STAILQ_EMPTY( &gptr->regexps ) )
        {
            rptr = STAILQ_FIRST( &gptr->regexps );
            STAILQ_REMOVE_HEAD( &gptr->regexps, next );
            free( rptr->exp );
#ifdef HAVE_LIBPCRE2
            pcre2_code_free( rptr->re );
#else
            regfree( &rptr->re );
#endif
            free( rptr );
        }
        while( !STAILQ_EMPTY( &gptr->hosts ) )
        {
            hptr = STAILQ_FIRST( &gptr->hosts );
            STAILQ_REMOVE_HEAD( &gptr->hosts, next );
            free( hptr->hostname );
            free( hptr );
        }
        free( gptr );
    }

    // reset the error code that caused us to exit
    errno = rc;

    return EXIT_SUCCESS;
}

// The main program
int main( int argc, char *argv[] )
{
    int rc;

    // open syslog
#ifdef LOG_SECURITY
    openlog( "banhammer", LOG_PID, LOG_SECURITY );     // FreeBSD style
#else
    openlog( "banhammer", LOG_PID, LOG_AUTH );         // Apple style
#endif

    // see if we are root
    if( geteuid( ) != 0 )
    {
        syslog( LOG_ALERT, "Banhammer has to be run as root." );
        closelog( );
        errx( EX_OSERR, "Banhammer has to be run as root." );
    }

    // initialize firewall
    rc = fw_init( );
    if( rc )
    {
        syslog( LOG_ERR, "Error initializing IPFW (rc=%d).", rc );
        closelog( );
        errx( EX_CONFIG, "Error initializing IPFW (rc=%d).", rc );
    }

    // initialize PRNG
    srandomdev( );

    // setup signal handlers
    signal( SIGINT, signalHandler );
    signal( SIGINFO, signalHandler );
    signal( SIGHUP, signalHandler );
    siginterrupt( SIGHUP, 1 );

    // initialize and run while necessary (allows re-initializing via SIGHUP)
    do
    {
        rc = mainLoop( argc, argv );
        // reset getopt framework in case we restart due to SIGHUP
        optreset = 1; opterr = 1; optind = 1;
    }
    while( errno == EINTR );

    // We are done here, clean up
    fw_close( );
    closelog( );

    return rc;
}

