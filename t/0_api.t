#!/usr/bin/perl

use strict;
use blib;
use warnings;
use File::Spec;
use Cwd;
use Test::More tests => 57;
use vars qw($host $p $FH $scaninfo @test %test $test);
use_ok('Nmap::Parser::XML');

$p = new Nmap::Parser::XML;
$scaninfo = new Nmap::Parser::XML::ScanInfo;
$host = new Nmap::Parser::XML::Host;

my @ScanInfo = qw(
args
finish_time
nmap_version
num_of_services
proto_of_scan_type
scan_types
start_time
);

my @Host = qw(
addr
addrtype
extraports_count
extraports_state
hostname
hostnames
ipidsequence
os_class
os_family
os_match
os_matches
os_port_used
status
tcp_port_state
tcp_ports
tcp_ports_count
tcp_service_name
tcp_service_proto
tcp_service_rpcnum
tcpsequence
tcptssequence
udp_port_state
udp_ports
udp_ports_count
udp_service_name
udp_service_proto
udp_service_rpcnum
uptime_lastboot
uptime_seconds
);

my @Std = qw(
clean
del_host
filter_by_osfamily
filter_by_status
get_host
get_host_list
get_host_objects
get_osfamily_list
get_scaninfo
parse
parse_filters
parsefile
register_host_callback
reset_host_callback
safe_parse
safe_parsefile
set_osfamily_list

);


isa_ok( $p , 'Nmap::Parser::XML');
isa_ok( $scaninfo,'Nmap::Parser::XML::ScanInfo');
isa_ok( $host,'Nmap::Parser::XML::Host');
for(sort @Std){can_ok($p,$_);}
for(sort @ScanInfo){can_ok($scaninfo,$_);}
for(sort @Host){can_ok($host,$_);}
