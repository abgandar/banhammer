<?php require_once('oben.php.inc'); ?>
<h1>Banhammer</h1>

<div style="float: right; width: 30%; float: right; margin-left: 20px; font-size: 75%; text-align: center;"/>
   <img src="daemon_hammer_small.png" alt="Beasty wielding the banhammer" style="width: 100%;"/><br/>
   <a href="http://www.freebsd.org/copyright/daemon.html">Beastie</a> the FreeBSD Daemon wielding the almighty banhammer
</div>

<p>
   Banhammer allows system administrators to dynamically adjust firewall
   rules in real time. The program analyzes system logs as they are written,
   extracts IP addresses, and adds them into IPFW tables. Depending on the
   firewall configuration, this allows to block, throttle or otherwise handle
   IP traffic by those addresses.<br/>
   Addresses are automatically purged from the tables after specified time.
   Banhammer uses regular expressions (POSIX or PCRE) to parse the logs, which
   gives great flexibility to the user. This allows banhammer to be used with
   virtually any network service capable of logging through syslog. Banhammer
   is written in pure C, has a very small memory footprint, doesn't rely on any
   external programs and communicates with IPFW directly via sockets.
</p>

<h2 style="clear: both;">How it works</h2>
<p>
   Banhammer consists of two separate main binaries: banhammer and banhammerd.
   <b>banhammer</b> is intended to be used in <i>/etc/syslog.conf</i> to pipe logs into.
   It performs the log analysis and adds addresses to IPFW tables. Along with
   the IP address, every entry in the IPFW tables has an additional value, which
   is used by banhammer to store the expiration date of the entry.
   <b>banhammerd</b> can be run in several ways. It can be a daemon, which checks
   IPFW tables periodically and removes expired entries. It can also be
   called to just purge the IPFW tables once, and exit afterwards. This is
   useful if you want to call banhammerd from cron. For administrators,
   banhammerd can simply print a list of currently blocked addresses and
   their expiration date.
</p>
<p>
   This design allows to avoid any IPC between banhammer and banhammerd. It
   also makes it easy for the administrator to edit the list of currently
   blocked addresses manually using system tools, such as
   <a href="http://www.freebsd.org/cgi/man.cgi?query=ipfw&format=html">ipfw(8)</a>,
   should it become neccessary.
</p>

<h2>System requirements</h2>
<p>
Banhammer requires <a href="http://www.freebsd.org/">FreeBSD</a> 8 or above
(tested on FreeBSD 9 and 10) with the IPFW firewall (version 2 or 3). IPv6
support is only available starting with FreeBSD 9.0.</p>
<p>Additionally, to provide even greater flexibility with regular expressions,
it is possible to compile banhammer with the <a href="http://www.pcre.org/">
PCRE library</a> instead of the default POSIX regular expressions. PCRE can
be installed easily from the FreeBSD ports tree (<a href="http://www.freshports.org/devel/pcre/">devel/pcre</a>).
</p>
<p>
Note that while Apple's Mac OS X comes with IPFW, it is deprecated and a very 
old version that does not even support tables. Therefore banhammer does not 
work on Mac OS X at all.
</p>

<h2>Download</h2>
<p>
Download the source code of banhammer v0.2: 
<a href="/files/banhammer/banhammer-latest.tar.gz">banhammer-0.2.tar.bz2</a>.
Banhammer is also available in the <a href="http://www.freshports.org/security/banhammer/">
FreeBSD ports tree</a> and hence also as a package. You can usually install it
simply by typing "<code>pkg install security/banhammer</code>".
</p>
<p>
The <a href="changelog.html">Changelog</a> contains a list of all major changes
between versions.</p>
<p>See the <a href="readme.html">README</a> for installation instructions and 
configuration examples, as well as the <a href="man.html">man page</a> for 
a detailed description of all configuration options.
</p>

<h2>License</h2>
<p>
Banhammer is distributed under the terms of the "BSD" license, as specified 
below. All documentation for Banhammer, supplied with the source code or on 
this website, is distributed under the same terms as the software itself.
</p>
<p>
Banhammer is based in part on <a href="http://samm.kiev.ua/bruteblock">Bruteblock</a> 
by Alex Samorukov.
</p>

<p>
 Copyright 2007-2015 Alexander Wittig. All rights reserved.
</p>
<p> 
 Redistribution and use in source and binary forms, with or without 
 modification, are permitted provided that the following conditions are met:
</p>
<p><ol> 
 <li>Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.</li>
 <li>Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.</li>
</ol></p>
<p>  
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
</p>
<?php require_once('unten.php.inc'); ?>

