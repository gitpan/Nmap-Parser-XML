#!/usr/bin/perl


use strict;
use Nmap::Parser::XML;
use constant TEST_FILE => 'ex_1.xml';
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

	for my $port ($host->tcp_ports())
	{ #all ports gotten from tcp_ports were open
     	#this prints out a line like:
	#127.0.0.1,21,OPEN,ftp,linux
	#address,port,state,service,os_matches
	print $host->addr().','.$port.',OPEN,'.
	$host->tcp_service_name($port).','.$host->os_matches(1)."\n";
	}

}
close OUT;


