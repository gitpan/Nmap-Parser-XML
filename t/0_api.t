#!/usr/bin/perl

use strict;
use blib;
use warnings;
use File::Spec;
use Cwd;
use Test::More tests => 52;
use vars qw($host $p $FH $scaninfo @test %test $test);
use_ok('Nmap::Parser::XML');

$p = new Nmap::Parser::XML;
$scaninfo = new Nmap::Parser::XML::ScanInfo;
$host = new Nmap::Parser::XML::Host;

my @ScanInfo = qw(
num_of_services start_time finish_time nmap_version args scan_types
proto_of_scan_type
);

my @Host = qw(
uptime_lastboot uptime_seconds os_family os_port_used os_matches udp_service_name
tcp_service_name tcp_service_proto udp_service_proto tcp_service_rpcnum
udp_service_rpcnum tcp_ports_count udp_ports_count udp_ports tcp_ports
hostname hostnames addrtype addr status tcpsequence ipidsequence
tcptssequence os_class
);

my @Std = qw(
clean get_host_list get_host del_host get_host_objects filter_by_osfamily
filter_by_status get_scaninfo safe_parse safe_parsefile parse parsefile parse_filters
get_osfamily_list set_osfamily_list register_host_callback reset_host_callback
);


isa_ok( $p , 'Nmap::Parser::XML');
isa_ok( $scaninfo,'Nmap::Parser::XML::ScanInfo');
isa_ok( $host,'Nmap::Parser::XML::Host');
for(sort @Std){can_ok($p,$_);}
for(sort @ScanInfo){can_ok($scaninfo,$_);}
for(sort @Host){can_ok($host,$_);}
