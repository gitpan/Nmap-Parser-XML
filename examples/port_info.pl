#!/usr/bin/perl
#Anthony G. Persaud
#port_info.pl
#Description:
#	It takes in a nmap xml file and outputs onto STDOUT and a file the
#	all the ports that were scanned and found by nmap, their different
#	states and services -- all in a comma delimited output
#
#This script produces this output with the nmap_results.xml file
#127.0.0.6,22,open,ssh,solaris,switch
#127.0.0.6,23,filtered,telnet,solaris,switch
#127.0.0.6,80,open,http,solaris,switch
#127.0.0.6,135,filtered,loc-srv,solaris,switch
#127.0.0.1,22,filtered,ssh,linux
#127.0.0.1,25,filtered,smtp,linux
#127.0.0.1,80,open,http,linux
#127.0.0.1,111,open,rpcbind,linux
#127.0.0.1,443,open,https,linux
#127.0.0.1,631,open,ipp,linux
#127.0.0.4,22,filtered,ssh,
#127.0.0.4,23,filtered,telnet,
#127.0.0.4,80,filtered,http,
#127.0.0.4,135,filtered,loc-srv,
#
#
#This program is free  software; you can redistribute  it and/or modify it under
#the terms of the  GNU General Public License  as published by the Free Software
#Foundation; either  version 2  of the  License, or  (at your  option) any later
#version.
#
#This program is distributed in the hope that it will be useful, but WITHOUT ANY
#WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
#PARTICULAR PURPOSE.  See the GNU General Public License for more details.

use strict;
use Nmap::Parser::XML;
use constant TEST_FILE => 'example.xml';
use constant OUT_FILE => 'port_info_out.csv';
use File::Spec;

my $FH = shift;
$FH ||= File::Spec->catfile(File::Spec->curdir(),    TEST_FILE);
$FH ||= File::Spec->catfile(File::Spec->curdir(),'examples',TEST_FILE) if(! -e $FH);
my $OUT = shift || OUT_FILE;
my $p = new Nmap::Parser::XML;

print "Usage: $0 [input.xml] [output.csv]\n";
print "\nUsing file: $FH\n\n";

$p->parse_filters({only_active => 1});
$p->parsefile($FH);
#open your output file (comma delimited)
open OUT, '>'.$OUT || die "Could not open output file: $OUT\n $!";
#after parsing, get the host objects
for my $host ($p->get_host_objects())
{
#treat $host as if it was a Nmap::Parser::XML::Host object

	#you could do this for udp also
	for my $port ($host->tcp_ports())
	{ #all ports gotten from tcp_ports were open
     	#this prints out a line like:
	#127.0.0.1,21,OPEN,ftp,linux
	#address,port,state,service,os_family
	print OUT $host->addr().','.$port.','.$host->tcp_port_state($port).','.$host->tcp_service_name($port).','.$host->os_family()."\n";
	print STDERR $host->addr().','.$port.','.$host->tcp_port_state($port).','.$host->tcp_service_name($port).','.$host->os_family()."\n";
	#tcp_service_name(portnumber) returns the service name running on that TCP port
	#you could, instead use os_class if available (available in Nmap::Parser::XML 0.64 and later
	#or, you could use the os_family() function and set up your os list
	}

}
close OUT;
print "\n\nOutput file generated: $OUT\n";
exit;

__END__


