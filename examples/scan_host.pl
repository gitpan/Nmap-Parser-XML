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
use Pod::Usage;
use vars qw(%G);
use constant CMD1 => 'nmap -sS -O -v -v -v -oX - ';
use constant CMD2 => 'nmap -sT -O -F -v -v -v -oX - ';
use constant TEST_FILE => 'example.xml';

Getopt::Long::Configure('bundling');


my $p = new Nmap::Parser::XML;

print "\nScan Host\t".(scalar localtime)."\n",('-'x50),"\n\n";
GetOptions(
		'help|h|?'		=> \$G{helpme},
		'F'		=> \$G{fast},
		'v+'		=> \$G{verbose},
		'i=s'		=> \$G{usefile},
) or (pod2usage(-exitstatus => 0, -verbose => 1));

if($G{helpme} || ($G{usefile} eq '' && scalar @ARGV == 0))
	{pod2usage(-exitstatus => 0, -verbose => 1)}

#Setup parser callback
$p->register_host_callback(\&host_handler);



#If using input file, then don't run nmap and use file
if($G{usefile} eq ''){$p = run_nmap_scan(@ARGV);}
else {
	#use the input file
	print 'Using InputFile: '.$G{usefile}."\n" if($G{verbose} > 0);
	if(not -e $G{usefile})
	{print STDERR "ERROR: File $G{usefile} does not exists!\n"; exit;}
	$p->parsefile($G{usefile});
	}

#This host handler will get call for every host that is scanned (or found in the
#xml file)

sub host_handler {
my $host = shift;
print ' > '.$host->addr."\n";
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
	printf("\t\t%-6s %-20s %s\n",
			$port,
			$host->tcp_service_name($port),
			$host->tcp_service_product($port).' '.
			$host->tcp_service_version($port));
	}

	print "\t[+] UDP Ports :\n" if($host->udp_ports_count);
	for my $port ($host->udp_ports()){
	printf("\t\t%-6s %-20s %s\n",
			$port,
			$host->udp_service_name($port),
			$host->udp_service_product($port).' '.
			$host->udp_service_version($port));
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
            next unless -r $path && (-x _ || -l _);

            return $path;
            last DIR;
        }
    }

}

sub run_nmap_scan {
my @ips =  grep {/(?:\d+\.){3}\d+/} @_;
my $NMAP;
	my $cmd;
	if($G{fast}){
	print "FastScan enabled\n" if($G{verbose} > 0 && $G{fast});
	$cmd = join ' ', (CMD2, @ips);
	} else {
	$cmd = join ' ', (CMD1, @ips);
	}


	my $nmap_exe = find_exe('nmap');
	if($nmap_exe eq '')
	{print STDERR "ERROR: nmap executable not found in \$PATH\n";exit;}

	print 'Running: '.$cmd."\n" if($G{verbose} > 0);

	open $NMAP , "$cmd |" || die "ERROR: $!\n";
	$p->parse($NMAP);
	close $NMAP;
return $p;
}

__END__
=pod

=head1 NAME

scan_host - a scanning script to gather port and OS information from hosts

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

These options are passed as command line parameters.

=over 4

=item B<-i nmapscan.xml>

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

=head1 OUTPUT EXAMPLE

These are ONLY examples of how the output would look like.

 Scan Host
 --------------------------------------------------
 [>] 127.0.0.1
       [+] Status: (UP)
       [+] Hostname(s) :
               localhost.localdomain
       [+] Operation System(s) :
               Linux Kernel 2.4.0 - 2.5.20
       [+] TCP Ports :
               22     ssh                  OpenSSH 3.5p1
               25     smtp
               111    rpcbind
               443    https
               631    ipp
       [+] UDP Ports :
               111    rpcbind
               937    unknown


=head1 SEE ALSO

L<Nmap::Parser::XML>

The Nmap::Parser::XML page can be found at:
L<http://www.public.iastate.edu/~ironstar/Nmap-Parser-XML/>. It contains
the latest developments on the module. The nmap security scanner homepage can
be found at: L<http://www.insecure.org/nmap/>.

=head1 AUTHOR

 Anthony G Persaud <ironstar@iastate.edu>

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

L<http://www.opensource.org/licenses/gpl-license.php>

=cut
