#!/usr/bin/perl
#This script produces comma delimited output

use strict;
use Nmap::Parser::XML;
use constant TEST_FILE => 'basic.xml';
use File::Spec;

my $FH = shift;
$FH ||= File::Spec->catfile(File::Spec->curdir(),    TEST_FILE);
$FH ||= File::Spec->catfile(File::Spec->curdir(),'examples',TEST_FILE) if(! -e $FH);

my $p = new Nmap::Parser::XML;

print "\nUsing file: $FH\n\n";
$p->parse_filters({only_active => 1});
$p->parsefile($FH);
#open your output file (comma delimited)
open OUT, '>comma_delimited.txt' || die;

#after parsing, get the host objects
for my $host ($p->get_host_objects())
{
#treat $host as if it was a Nmap::Parser::XML::Host object

	#you could do this for udp also
	for my $port ($host->tcp_ports())
	{ #all ports gotten from tcp_ports were open
     	#this prints out a line like:
	#127.0.0.1,21,OPEN,ftp,linux
	#address,port,state,service,os_matches
	print OUT $host->addr().','.$port.',OPEN,'.$host->tcp_service_name($port).','.$host->os_family()."\n";
	print STDERR $host->addr().','.$port.',OPEN,'.$host->tcp_service_name($port).','.$host->os_family()."\n";
	#tcp_service_name(portnumber) returns the service name running on that TCP port
	#os_matches(1) returns the first os_match
	#you could, instead use os_class (available in Nmap::Parser::XML 0.64 >
	#or, you could use the os_family() function and set up your os list
	}

}
close OUT;

exit;

__END__
#This script produces this output with the basic.xml file in the t/ directory
#127.0.0.1,25,OPEN,smtp,linux
#127.0.0.1,22,OPEN,ssh,linux
#127.0.0.1,631,OPEN,ipp,linux
#127.0.0.1,443,OPEN,https,linux
#127.0.0.1,111,OPEN,rpcbind,linux
#127.0.0.1,80,OPEN,http,linux
#127.0.0.2,22,OPEN,ssh,solaris
#127.0.0.2,80,OPEN,http,solaris

