#!/usr/bin/perl
#Anthony G. Persaud
#port_info.pl
#Description:
#	It takes in a nmap xml file and outputs onto STDOUT and a file the
#	all the ports that were scanned and found by nmap, their different
#	states and services -- all in a comma delimited output
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
use Getopt::Long;
use File::Spec;
#Lets you have options like -st equivalent to (-s -t)
Getopt::Long::Configure('bundling');
use Pod::Usage;
use vars qw(%G);
my $p = new Nmap::Parser::XML;


########################
use constant TEST_FILE => 'example.xml';
use constant OUT_FILE => 'port_info_out.csv';
use File::Spec;

my $FH;
$FH ||= File::Spec->catfile(File::Spec->curdir(),    TEST_FILE);
$FH = File::Spec->catfile(File::Spec->curdir(),'examples',TEST_FILE) if(! -e $FH);
########################
print "\nScan Host\t\tv0.69\n",('-'x60),"\n";
my $val = GetOptions(
		'help|h|?'		=> \$G{helpme},
		'F'		=> \$G{fast},
		'v+'		=> \$G{verbose},
		'f=s'		=> \$G{usefile},
) or (pod2usage(-exitstatus => 0, -verbose => 1));

if($G{helpme}){pod2usage(-exitstatus => 0, -verbose => 1)}
#Setup parser callback
$p->register_host_callback(\&host_handler);
#just in case nothing is passed
if($G{usefile} eq '' && scalar @ARGV == 0){$G{usefile} = TEST_FILE;}




#If using input file, then don't run nmap and use file
if($G{usefile} eq ''){
	my @ips = @ARGV;
	my $NMAP;
	my $cmd;
	if($G{fast}){
	print "FastScan enabled\n" if($G{verbose} > 0 && $G{fast});
	$cmd = join ' ', ('nmap -sS -O -v -v -v -oX - ', @ips);
	} else {
	$cmd = join ' ', ('nmap -sT -O -F -v -v -v -oX - ', @ips);
	}


	my $nmap_exe = find_exe('nmap');
	if($nmap_exe eq '')
	{print STDERR "ERROR: nmap executable not found in \$PATH\n";exit;}

	print 'Running: '.$cmd."\n" if($G{verbose} > 0);

	open $NMAP , "$cmd |" || die "ERROR: $!\n";
	$p->parse($NMAP);
	close $NMAP;

}
elsif (not -e $G{usefile}){
	print STDERR "ERROR: File $G{usefile} does not exists!\n";exit;

} else {
	#use the input file
	print 'Using InputFile: '.$G{usefile}."\n" if($G{verbose} > 0);
	$p->parsefile($G{usefile});
	}

#This host handler will get call for every host that is scanned (or found in the
#xml file)

sub host_handler {
my $host = shift;
print $host->addr."\n";
print "\t[+] Status: (".uc($host->status).")\n";
if($host->status ne 'up'){goto END;}
	tab_print("Hostname(s)",$host->hostnames());
	tab_print("Operation System(s)",$host->os_matches());
	port_service_print($host);
END:
print "\n\n";
}


#Quick function to print witht tabs
sub tab_print {print "\t[+] $_[0] :\n";shift;for my $a (@_){print "\t\t$a\n";}}
sub port_service_print {
my $host = shift;
print "\t[+] TCP Ports :\n";
for my $port ($host->tcp_ports()){
printf("\t\t%-6s %-20s %s\n", $port, $host->tcp_service_name($port), $host->tcp_service_product($port).' '.$host->tcp_service_version($port));
}

print "\t[+] UDP Ports :\n" if($host->udp_ports_count);
for my $port ($host->udp_ports()){
printf("\t\t%-6s %-20s %s\n", $port, $host->udp_service_name($port), $host->udp_service_product($port).' '.$host->udp_service_version($port));
}

}

#quick function to find an executable in a given path
sub find_exe {
shift if(ref($_[0]) eq caller());

    my $exe_to_find = shift;
    $exe_to_find =~ s/\.exe//;
    local($_);
    local(*DIR);

    for my $dir (File::Spec->path()) {
        opendir(DIR,$dir) || next;
        my @files = (readdir(DIR));
        closedir(DIR);

        my $path;
        for my $file (@files) {
            $file =~ s/\.exe$//;
            next unless($file eq $exe_to_find);

            $path = File::Spec->catfile($dir,$file);
            #  Should symbolic link be considered?  Helps me on cygwin but ...
            next unless -r $path && (-x _ || -l _);

            return $path;
            last DIR;
        }
    }

}

__END__


=pod

=head1 NAME

ScanHost - simple scanning script to gather information from various hosts
using the nmap security scanner and the Nmap::Parser::XML module.

=head1 SYNOPSIS

 scan_host.pl [OPTS] <IP_ADDR> [<IP.ADDR> ...]

=head1 DESCRIPTION

This script uses the nmap security scanner with the Nmap::Parser::XML module
in order to run quick scans against specific hosts, and gather all the
information that is required to know about that specific host which nmap can
figure out. This script can be used for quick audits against machines on the
network and an educational use for learning how to write scripts using the
Nmap::Parser::XML module.

=head1 OPTIONS

These options are passes as command line parameters.

=over 4

=item B<-f nmapscan.xml>

Runs the script using the given xml file (which is nmap xml scan data) instead
of actually running a scan against the given set of hosts. This is useful if
you only have the xml data on a given machine, and not nmap.

=item B<--fast>

Runs a fast (-F) nmap scan against the host.

=item B<-h,--help,-?>

Shows this help information.

=item B<-v>

This runs the script in verbose mode. The more times used, the more verbose
the script will be.

=back 4

=head1 AUTHOR

 Anthony G Persaud <ironstar@iastate.edu>

=cut
