#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 11;
use Nmap::Parser::XML;
use constant FIRST =>  0;
use constant SECOND => 1;
use constant THIRD =>  2;
use constant HOST1 => '127.0.0.1';
use constant HOST2 => '127.0.0.2';
use constant HOST3 => '127.0.0.3';
use constant HOST4 => '127.0.0.4';
use constant HOST5 => '127.0.0.5';
use constant HOST6 => '127.0.0.6';

use constant TEST_FILE =>'nmap_results.xml';
use vars qw($p $FH @up @down $total_count);



$FH = File::Spec->catfile(cwd(),'t',TEST_FILE);
$FH = File::Spec->catfile(cwd(),    TEST_FILE)  unless(-e $FH);

$p = new Nmap::Parser::XML;
isa_ok($p, 'Nmap::Parser::XML');
ok($p->register_host_callback(\&my_callback),'Registering callback funciton');
is($p->reset_host_callback(),undef,'Reset host callback');
ok($p->register_host_callback(\&my_callback),'Registering callback funciton again');
ok($p->parsefile($FH),'Parsing from nmap data: $FH');
ok($p->parse_filters({scaninfo => 0}), 'Setting parse filter (no scaninfo)');

sub my_callback {
my $host = shift;
my $addr = $host->addr();
if($addr =~ /127\.0\.0\./){
$total_count++;}
if($host->status eq 'up'){push @up, $addr;}
elsif($host->status eq 'down'){push @down, $addr;}
}

#TESTING CALLBACK OUTPUT
ok(eq_set([@up], [HOST1,HOST2, HOST4, HOST5, HOST6]), 'Testing for correct up hosts');
ok(eq_set([@down], [HOST3]), 'Testing for correct down hosts');
is($total_count, 6, 'Testing for correct callback paramater passing');

#CHECKING FOR DELETION
my $test = $p->get_host(HOST1);
is($test , undef, 'Making sure hosts do not exists');
my @hosts = $p->get_host_objects();
is(scalar @hosts, 0 , 'Making sure objects were deleted after callback');



