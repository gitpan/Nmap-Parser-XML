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
$p->parsefile($FH);
print "Active Hosts Scanned:\n";
for my $ip ($p->get_host_list('up')){print "\t$ip\n";}
print "\n";
print "Inactive Hosts Scanned:\n";
for my $ip ($p->get_host_list('down')){print "\t$ip\n";}


