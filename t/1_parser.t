#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 200;
use Nmap::Parser::XML;
use constant FIRST => 0;
use constant SECOND => 1;
use constant THIRD => 2;
use constant HOST1 => '127.0.0.1';
use constant HOST2 => '127.0.0.2';
use constant HOST3 => '127.0.0.3';
use constant HOST4 => '127.0.0.4';
use constant HOST5 => '127.0.0.5';
use constant HOST6 => '127.0.0.6';




use constant TEST_FILE =>'nmap_results.xml';
use vars qw($host $p $FH $scaninfo @test %test $test);



$FH = File::Spec->catfile(cwd(),'t',TEST_FILE);
$FH = File::Spec->catfile(cwd(),    TEST_FILE)  unless(-e $FH);

$p = new Nmap::Parser::XML;

nmap_parse_filter_test();
nmap_parse_test();
nmap_parse_std_test();
nmap_parse_scaninfo_test();
nmap_parse_host_test_1();
nmap_parse_host_test_2();
nmap_parse_host_test_3();
nmap_parse_host_test_4();
nmap_parse_host_test_5();
nmap_parse_host_test_6();
nmap_parse_end_test();

################################################################################
##									      ##
################################################################################
sub nmap_parse_test {ok($p->parsefile($FH),'Parsing from nmap data: $FH');}

sub nmap_parse_end_test {
ok($p->del_host(HOST2),'Testing del_host');
ok(!$p->get_host(HOST2),'Testing for permanent deletion from call');
ok(eq_set([$p->get_host_list('up')],[HOST1, HOST4, HOST5, HOST6]),'Testing for permanent deletion from list');
ok($p->clean(),'Testing clean() to clean memory');
ok(!$p->get_scaninfo(),'Testing clean() against scaninfo');
is(scalar $p->get_host_list(),0,'Testing clean() against host list');

}

################################################################################
##									      ##
################################################################################
sub nmap_parse_std_test {


%test = (solaris => [qw(solaris sparc sun)],
            linux => [qw(linux mandrake redhat slackware)],
            unix => [qw(unix hp-ux hpux bsd immunix aix)],
            win  => [qw(win microsoft workgroup)],
	    mac => [qw(mac osx)],
	    switch => [qw(ethernet cisco netscout router switch bridge)],
	    wap => [qw(wireless wap)]
	    );

#OSFAMILY LIST
is_deeply($p->get_osfamily_list(),\%test, 'Testing default get_osfamily_list');
%test = (solaris => [qw(solaris sparc sun)],linux => [qw(linux mandrake redhat slackware)]);
is_deeply($p->set_osfamily_list(\%test),\%test, 'Testing set_osfamily_list');
is_deeply($p->get_osfamily_list(),\%test, 'Testing get_osfamily_list for premanence of structure');

#GET HOST LIST
ok(eq_set([$p->get_host_list()],[HOST1, HOST2, HOST3, HOST4, HOST5, HOST6]), 'Testing get_host_list for correct hosts from file');
ok(eq_set([$p->get_host_list('up')],[HOST1,HOST2, HOST4, HOST5, HOST6]), 'Testing get_host_list for correct hosts with status = up');
ok(eq_set([$p->get_host_list('down')],[HOST3]), 'Testing get_host_list for correct hosts for with status = down');

#FILTER BY OSFAMILY
ok(eq_set([$p->filter_by_osfamily('solaris')],[HOST2, HOST6]),'Testing single osfamily filter');
ok(eq_set([$p->filter_by_osfamily('solaris','linux')],[HOST2,HOST1,HOST6]), 'Testing multiple osfamily filter');

#FILTER BY STATUS
ok(eq_set([$p->filter_by_status('up')],[HOST1,HOST2, HOST4, HOST5, HOST6]),'Testing status filter - up');
ok(eq_set([$p->filter_by_status('down')],[HOST3]),'Testing status filter - down');
ok(eq_set([$p->filter_by_status()],[HOST1,HOST2, HOST4, HOST5, HOST6]),'Testing status filter - default');

@test = sort {$a->addr() cmp $b->addr()} $p->get_host_objects();
is(scalar @test, 6,'Testing for number of host objects');

#ADDR TEST
is($test[FIRST]->addr(), HOST1,'Testing for host object 1');
is($test[SECOND]->addr(), HOST2,'Testing for host object 2');
is($test[THIRD]->addr(), HOST3,'Testing for host object 3');

}

################################################################################
##									      ##
################################################################################
sub nmap_parse_scaninfo_test {
isa_ok($scaninfo = $p->get_scaninfo(), 'Nmap::Parser::XML::ScanInfo');

#BASIC
is($scaninfo->nmap_version(),'3.27','Testing nmap version');
is($scaninfo->xml_version(),'1.0','Testing xmloutput version');
is($scaninfo->args(),'nmap -v -v -v -oX test.xml -O -sTUR -p 1-1023 localhost','Testing nmap arguments');

#NUM OF SERVICES
is($scaninfo->num_of_services(), (1023+1023), 'Testing total number of services');
is($scaninfo->num_of_services('connect'), 1023, 'Testing number of services for CONNECT');
is($scaninfo->num_of_services('udp'),1023, 'Testing number of services for UDP');

#SCAN TIME
is($scaninfo->start_time(),1057088883,'Testing scaninfo start time');
is($scaninfo->finish_time(),1057088900,'Testing scaninfo finish time');

#SCAN TYPES
is(scalar $scaninfo->scan_types() ,2, 'Testing number of scan types');
ok(eq_set( [$scaninfo->scan_types()], ['connect','udp']), 'Testing for correct scan types');

#PROTO OF SCAN TYPE
is($scaninfo->proto_of_scan_type('connect'), 'tcp','Testing "connect" protocol = tcp');
is($scaninfo->proto_of_scan_type('udp'), 'udp','Testing "udp" protocol = udp');
}

################################################################################
##									      ##
################################################################################
sub nmap_parse_host_test_1 {
print "\n\nTesting ".HOST1."\n";
isa_ok($host = $p->get_host(HOST1),'Nmap::Parser::XML::Host');

#BASIC
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), HOST1, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');

#HOSTNAMES
is($host->hostname(), 'localhost.localdomain','Testing basic hostname()');
is($host->hostnames(), 1,'Testing for correct hostname count (void)');
is($host->hostnames(1), 'localhost.localdomain','Testing for correct hostname (1)');

#PORTS
is($host->extraports_state(),'closed','Testing extraports_state');
is($host->extraports_count(),2038,'Testing extraports_count');

is(scalar @{[$host->tcp_ports()]} , 6, 'Testing for tcp_ports(6)');
is(scalar @{[$host->udp_ports()]} , 2, 'Testing for udp_ports(2)');

is($host->tcp_ports_count , 6, 'Testing for tcp_ports_count(6)');
is($host->udp_ports_count , 2, 'Testing for udp_ports_count(2)');


is_deeply([$host->tcp_ports()],[qw(22 25 80 111 443 631)],'Testing tcp ports found');
is_deeply([$host->udp_ports()],[qw(111 937)],'Testing udp ports found');
is_deeply([$host->tcp_ports('open')],[qw(80 111 443 631)],'Testing tcp ports "open"');
is_deeply([$host->tcp_ports('filtered')],[qw(22 25)],'Testing tcp ports "filtered"');
is_deeply([$host->udp_ports('open')],[qw(111)],'Testing udp ports "open"');
is_deeply([$host->udp_ports('closed')],[qw(937)],'Testing udp ports "closed"');



is($host->tcp_port_state('22'),'filtered','Testing tcp_ports(port_number) filtered');
is($host->udp_port_state('111'),'open','Testing udp_ports(port_number) open');
is($host->udp_port_state('9999'),'closed','Testing udp_ports(port_number) closed');



#TCP AND UDP SERVICE NAMES
is($host->tcp_service_name('22'), 'ssh','Testing tcp_service_name(22) = sshd');
is($host->tcp_service_name('25'), 'smtp','Testing tcp_service_name(25) = smtp');
is($host->udp_service_name('111'), 'rpcbind', 'Testing udp_service_name(111) = rpcbind');
#TEST tcp_service_proto,udp_service_proto,tcp_service_rpcnum,udp_service_rpcnum
is($host->tcp_service_proto('111'), 'rpc','Testing tcp_service_name(25) = smtp');

is($host->udp_service_proto('111'), 'rpc', 'Testing udp_service_proto(111)');
is($host->tcp_service_rpcnum('111'), 100000,'Testing tcp_service_rpcnum(111)');
is($host->udp_service_rpcnum('111'), 100000, 'Testing udp_service_rpcnum(111)');

#OS MATCHES
is(scalar @{[$host->os_matches()]} , 1,'Testing os_matches()');
is(scalar $host->os_matches(),1,'Testing for correct OS');
is($host->os_match, 'Linux Kernel 2.4.0 - 2.5.20','Testing os_match');
is($host->os_matches(1), 'Linux Kernel 2.4.0 - 2.5.20','Testing os_matches(1)');

#OS CLASS
is_deeply([$host->os_class(1)],['Linux','2.4.x','Linux','general purpose'],'Testing os_class() with arg 1');
is_deeply([$host->os_class(2)],['Solaris','8','Sun','general purpose'],'Testing os_class() with 2');
is($host->os_class(),2,'Testing total count of os_class tags');

#OSFAMILY
is($host->os_family(),'linux','Testing os_family() = linux');

#OS PORT USED
is($host->os_port_used(), 22, 'Testing os_port_used() with no arguments');
is($host->os_port_used('open'), 22, 'Testing os_port_used() using "open"');
is($host->os_port_used('closed'), 1, 'Testing os_port_used() using "closed"');

#SEQUENCES
is_deeply([$host->tcpsequence_class(), $host->tcpsequence_values(), $host->tcpsequence_index()],
          ['random positive increments','B742FEAF,B673A3F0,B6B42D41,B6C710A1,B6F23FC4,B72FA3A8',4336320],
          'Testing tcpsequence class,values,index');
is_deeply([$host->ipidsequence_class(),$host->ipidsequence_values()],['All zeros','0,0,0,0,0,0'],'Testing ipidsequence class,values');
is_deeply([$host->tcptssequence_class(), $host->tcptssequence_values()],['100HZ','30299,302A5,302B1,302BD,302C9,302D5'],'Testing tcptssequence class,values');

#UPTIME
is($host->uptime_seconds() , 1973, 'Testing uptime_seconds()');
is($host->uptime_lastboot() ,'Tue Jul  1 14:15:27 2003', 'Testing uptime_lastboot()');

}

################################################################################
##									      ##
################################################################################
sub nmap_parse_host_test_2 {
print "\n\nTesting ".HOST2."\n";
isa_ok($host = $p->get_host(HOST2),'Nmap::Parser::XML::Host');

#BASIC
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), HOST2, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');

#HOSTNAMES
is($host->hostname(), 'LocalHost 2','Testing basic hostname()');
is($host->hostnames(), 1,'Testing for correct hostname count (void)');
is($host->hostnames(1), 'LocalHost 2','Testing for correct hostname (1)');

#PORTS
is($host->extraports_state(),'closed','Testing extraports_state');
is($host->extraports_count(),2044,'Testing extraports_count');

is(scalar @{[$host->tcp_ports()]} , 2, 'Testing for tcp_ports(2)');
is(scalar @{[$host->udp_ports()]} , 0, 'Testing for udp_ports(0)');
print '|'.$_ .'|'for ($host->udp_ports());
is($host->tcp_ports_count , 2, 'Testing for tcp_ports_count(2)');
is($host->udp_ports_count , 0, 'Testing for udp_ports_count(0)');


is_deeply([$host->tcp_ports()],[qw(22 80)],'Testing tcp ports found');
is_deeply([$host->udp_ports()],[qw()],'Testing udp ports found');
is_deeply([$host->tcp_ports('open')],[qw(22 80)],'Testing tcp ports "open"');
is_deeply([$host->tcp_ports('filtered')],[qw()],'Testing tcp ports "filtered"');
is_deeply([$host->udp_ports('open')],[qw()],'Testing udp ports "open"');
is_deeply([$host->udp_ports('closed')],[qw()],'Testing udp ports "closed"');

is($host->tcp_port_state('22'),'open','Testing tcp_ports(port_number) open');
is($host->tcp_port_state('80'),'open','Testing tcp_ports(port_number) open');



#TCP AND UDP SERVICE NAMES
is($host->tcp_service_name('22'), 'ssh','Testing tcp_service_name(22) = sshd');
is($host->tcp_service_name('80'), 'http','Testing tcp_service_name(80) = http');
is($host->tcp_service_version('22'), '3.5p1','Testing tcp_service_name(22) = sshd');
is($host->tcp_service_version('80'), '2.0.40','Testing tcp_service_name(80) = http');

#OS MATCHES
is(scalar @{[$host->os_matches()]} , 1,'Testing os_matches()');
is(scalar $host->os_matches(),1,'Testing for correct OS');
is($host->os_matches(1), 'Sun Solaris 8 early access beta through actual release','Testing for correct OS');

#OS CLASS
is_deeply([$host->os_class(1) ],['Solaris','8','Sun','general purpose'],'Testing os_class() with no args');
is($host->os_class(),1,'Testing total count of os_class tags');

#OSFAMILY
is($host->os_family(),'solaris','Testing os_family() = solaris');

#SEQUENCES
is_deeply([$host->tcpsequence_class(), $host->tcpsequence_values(), $host->tcpsequence_index()],['truly random','4B1CC657,99519A3F,9F934F86,74DAA2B1,9A935F26,EC151FED',9999999],'Testing tcpsequence class,values,index');
is_deeply([$host->ipidsequence_class(),$host->ipidsequence_values()],['Incremental','FF62,FF63,FF64,FF65,FF66,FF67'],'Testing ipidsequence class,values');
is_deeply([$host->tcptssequence_class(),$host->tcptssequence_values()],['100HZ','AF591DD,AF591E9,AF591F5,AF59201,AF5920D,AF59219'],'Testing tcptssequence class,values');

#UPTIME
is($host->uptime_seconds() , 1838659, 'Testing uptime_seconds() : ');
is($host->uptime_lastboot() ,'Wed Jun 11 09:13:35 2003', 'Testing uptime_lastboot() : ');

}


################################################################################
##									      ##
################################################################################
sub nmap_parse_host_test_3 {
print "\n\nTesting ".HOST3."\n";
isa_ok($host = $p->get_host(HOST3),'Nmap::Parser::XML::Host');

#BASIC
is($host->status(), 'down', 'Testing if status = up');
is($host->addr(), HOST3, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');
}

################################################################################
##									      ##
################################################################################
sub nmap_parse_host_test_4 {
print "\n\nTesting ".HOST4."\n";
isa_ok($host = $p->get_host(HOST4),'Nmap::Parser::XML::Host');

#BASIC
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), HOST4, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');
is($host->hostname(), 'host1', 'Testing hostname');
#PORTS
is($host->extraports_state(),'closed','Testing extraports_state');
is($host->extraports_count(),1640,'Testing extraports_count');

is_deeply([$host->tcp_ports()],[qw(22 23 80 135)],'Testing tcp ports found');
is_deeply([$host->tcp_ports('filtered')],[qw(22 23 80 135)],'Testing tcp ports "filtered"');


is($host->tcp_port_state('22'),'filtered','Testing tcp_ports(port_number) filtered');
is($host->tcp_port_state('80'),'filtered','Testing tcp_ports(port_number) filtered');



#TCP AND UDP SERVICE NAMES
is($host->tcp_service_name('135'), 'loc-srv','Testing tcp_service_name(135) = loc-srv');
is($host->tcp_service_name('23'), 'telnet','Testing tcp_service_name(80) = telnet');

}


################################################################################
##									      ##
################################################################################
sub nmap_parse_host_test_5 {
print "\n\nTesting ".HOST5."\n";
isa_ok($host = $p->get_host(HOST5),'Nmap::Parser::XML::Host');

#BASIC
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), HOST5, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');
is($host->hostname(), 'host2', 'Testing hostname');
is($host->extraports_state(),'filtered','Testing extraports_state');
is($host->extraports_count(),1644,'Testing extraports_count');

is_deeply([$host->tcp_ports()],[qw(22 112 953)],'Testing tcp ports found');
is_deeply([$host->tcp_ports('open')],[qw(22 112 953)],'Testing tcp ports "open"');

is($host->tcp_port_state(22),'open','Testing tcp state open');

is($host->tcp_service_name(22),'ssh','Testing service name ssh');
is($host->tcp_service_name(112),'rpcbind','Testing service name rpcbind');
is($host->tcp_service_name(953),'rndc','Testing service name rndc');

is($host->tcp_service_version(22),'3.1p1','Testing service version 22');
is($host->tcp_service_product(22),'OpenSSH','Testing service product 22');
is($host->tcp_service_extrainfo(22),'protocol 1.99','Testing service info 22');

is($host->tcp_service_version(112),2,'Testing tcp service version 112');
is($host->tcp_service_version(953),undef,'Testing tcp service version 953');

}

################################################################################
##									      ##
################################################################################
sub nmap_parse_host_test_6 {
print "\n\nTesting ".HOST6."\n";
isa_ok($host = $p->get_host(HOST6),'Nmap::Parser::XML::Host');

#BASIC
is($host->status(), 'up', 'Testing if status = up');
is($host->addr(), HOST6, 'Testing for correct address');
is($host->addrtype(), 'ipv4', 'Testing for correct address type - ipv4');
is($host->hostname(), 'host7.net', 'Testing hostname');

is($host->tcp_service_extrainfo(111),'rpc #100000','Testing service info 111');
is($host->tcp_service_extrainfo(22),'protocol 1.99','Testing service info 22');
is($host->tcp_service_extrainfo(443),'(Red Hat Linux)','Testing service info 443');
is($host->tcp_service_extrainfo(6000),'access denied','Testing service info 6000');
is($host->tcp_service_extrainfo(80),'(Red Hat Linux)','Testing service info 80');

is($host->tcp_service_version(111),2,'Testing service name 111');
is($host->tcp_service_version(22),'3.5p1','Testing tcp service version 443');
is($host->tcp_service_version(443),'2.0.40','Testing tcp service version 443');
is($host->tcp_service_version(80),'2.0.40','Testing tcp service version 80');
is($host->tcp_service_version(6000),undef,'Testing tcp service version 6000');


is($host->tcp_service_product(22),'OpenSSH','Testing tcp service product: 22');
is($host->tcp_service_product(80),'Apache httpd','Testing tcp service product: 80');
is($host->tcp_service_product(443),'Apache httpd','Testing tcp service product: 443');


#OS MATCHES
is(scalar @{[$host->os_matches()]} , 9,'Testing os_matches()');
is(scalar $host->os_matches(),9,'Testing for correct OS');
is($host->os_matches(1), $host->os_match(),'Testing for correct OS 1');
is($host->os_matches(1), 'Redback SMS 1800/10000 router or Thomson TMC 390 cable modem','Testing for correct OS 1');
is($host->os_matches(2), 'Redback SMS 1800 router','Testing for correct OS 2');
is($host->os_matches(3), 'Fore ForeThought 7.1.0 ATM switch','Testing for correct OS 3');
is($host->os_matches(4), 'Xerox Docuprint N2125 network printer','Testing for correct OS 4');
is($host->os_matches(5), 'Redback SMS 1000-2000 DSL Router','Testing for correct OS 5');
is($host->os_matches(6), 'SonicWall SOHO firewall, Enterasys Matrix E1, or Accelerated Networks VoDSL, or Cisco 360 Access Point','Testing for correct OS 6');
is($host->os_matches(7), 'Alcatel 1000 DSL Router','Testing for correct OS 7');
is($host->os_matches(8), 'Sun RSC (Remote System Control card) v1.14 (in Solaris 2.7)','Testing for correct OS 8');
is($host->os_matches(9), 'Cisco 11151/Arrowpoint 150 load balancer, Neoware (was HDS) NetOS V. 2.0.1 or HP ENTRIA C3230A','Testing for correct OS 9');


#OS CLASS
is_deeply([$host->os_class(1) ],['AOS','','Redback','router'],'Testing os_class(1)');
is_deeply([$host->os_class(15)],['embedded','','3Com','WAP'],'Testing os_class(15)');

is($host->os_osfamily(1),'AOS','Testing os_osfamily');
is($host->os_vendor(1),'Redback','Testing os_vendor');
is($host->os_gen(1),undef,'Testing os_gen');
is($host->os_type(1),'router','Testing os_type');

is($host->os_osfamily(15),'embedded','Testing os_osfamily');
is($host->os_vendor(15),'3Com','Testing os_vendor');
is($host->os_gen(15),undef,'Testing os_gen');
is($host->os_type(15),'WAP','Testing os_type');


is($host->os_osfamily(20),'OpenBSD','Testing os_osfamily');
is($host->os_vendor(20),'OpenBSD','Testing os_vendor');
is($host->os_gen(20),'2.X','Testing os_gen');
is($host->os_type(20),'general purpose','Testing os_type');

is($host->os_class(),36,'Testing total count of os_class tags');

#OSFAMILY
is($host->os_family(),'solaris,switch','Testing os_family() = solaris,switch');

}


################################################################################
##									      ##
################################################################################
sub nmap_parse_filter_test {


%test = (
	osfamily	=> 0,
	osinfo		=> 0,
	scaninfo	=> 0,
	only_active	=> 0,
	sequences 	=> 0,
	portinfo	=> 0,
	uptime		=> 0,
	extraports	=> 0,
	);

is_deeply($p->parse_filters(\%test),\%test,'Testing parse filter set');

%test = (
	osfamily 	=> 0,
	osinfo		=> 0,
	scaninfo	=> 1,
	only_active	=> 1,
	sequences 	=> 0,
	portinfo	=> 0,
	uptime		=> 0,
	extraports	=> 0,
	);

is_deeply($p->parse_filters({only_active=>1,scaninfo=>1}),\%test,'Testing for filter permanence');
%test = (
	osfamily 	=> 1,
	osinfo		=> 1,
	scaninfo	=> 1,
	only_active	=> 0,
	sequences 	=> 1,
	portinfo	=> 1,
	uptime		=> 1,
	extraports	=> 1,
	);

is_deeply($p->reset_filters(),\%test,'Testing reset_filters()');

}
