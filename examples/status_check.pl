#!/usr/bin/perl
#Anthony G. Persaud
#status_check.pl
#Description:
#	It takes in a nmap xml file and prints a list of active and inactive
#	hosts.

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
use File::Spec;

my $FH = shift;
$FH ||= File::Spec->catfile(File::Spec->curdir(),    TEST_FILE);
$FH = File::Spec->catfile(File::Spec->curdir(),'examples',TEST_FILE) if(! -e $FH);

my $p = new Nmap::Parser::XML;
print "Usage: $0 [input.xml]\n";
print "\nUsing file: $FH\n\n";
$p->parsefile($FH);#parse the file
#printing active hosts
print "Active Hosts Scanned:\n";
for my $ip ($p->get_host_list('up')){print "\t$ip\n";}
print "\n";
#printing inactive hosts
print "Inactive Hosts Scanned:\n";
for my $ip ($p->get_host_list('down')){print "\t$ip\n";}


__END__
