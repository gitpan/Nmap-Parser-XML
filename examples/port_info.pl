#!/usr/bin/perl
#Anthony G. Persaud
#port_info.pl
#Description:
#	It takes in a nmap xml file and outputs onto STDOUT and a file the
#	all the ports that were scanned and found by nmap, their different
#	states and services -- all in a comma delimited output
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
use constant TEST_FILE => 'example.xml';
use constant OUT_FILE => 'port_info_out.csv';
use File::Spec;
use Pod::Usage;
use Getopt::Long;
use vars qw(%G);
use constant CMD1 => 'nmap -sS -v -v -v -oX - ';
use constant FAST_CMD => 'nmap -sT -F -v -v -v -oX - ';
Getopt::Long::Configure('bundling');

GetOptions(
		'help|h|?'	=> \$G{helpme},
		'F'		=> \$G{fast},
		'v+'		=> \$G{verbose},
		'i=s'		=> \$G{usefile},
		'o=s'		=> \$G{output}
) or (pod2usage(-exitstatus => 0, -verbose => 1));

if($G{helpme} || ($G{usefile} eq '' && scalar @ARGV == 0))
	{pod2usage(-exitstatus => 0, -verbose => 1);}

print "\nPort Info\t".(scalar localtime)."\n",('-'x50),"\n\n";


my $OUT = $G{output} || OUT_FILE;
my $p = new Nmap::Parser::XML;

$p->parse_filters({
	only_active => 1,
	osinfo => 1,
	scaninfo => 0,
	sequences      => 0
});

if($G{usefile} eq ''){$p = run_nmap_scan(@ARGV);}
else {
	#use the input file
	print 'Using InputFile: '.$G{usefile}."\n\n" if($G{verbose} > 0);
	if(not -e $G{usefile})
	{print STDERR "ERROR: File $G{usefile} does not exists!\n"; exit;}
	$p->parsefile($G{usefile});
	}


#open your output file (comma delimited)
open OUT, '>'.$OUT || die "Could not open output file: $OUT\n $!";
#after parsing, get the host objects
for my $host ($p->get_host_objects())
{
#treat $host as if it was a Nmap::Parser::XML::Host object

	#you could do this for udp also
	for my $port ($host->tcp_ports())
	{
	print OUT $host->addr().','.
	          $port.','.
	          $host->tcp_port_state($port).','.
	           'tcp,'.
	          $host->tcp_service_name($port).','.
	          $host->tcp_service_product($port).','.
	          $host->tcp_service_version($port).','.
	          $host->tcp_service_extrainfo($port).','.
	          $host->os_family()."\n";
	print STDOUT $host->addr().','.
	          $port.','.
	          $host->tcp_port_state($port).','.
	 	  'tcp,'.
	          $host->tcp_service_name($port).','.
	          $host->tcp_service_product($port).','.
	          $host->tcp_service_version($port).','.
	          $host->tcp_service_extrainfo($port).','.
	          $host->os_family()."\n";
	#you could, instead use os_class if available (available in Nmap::Parser::XML 0.64 and later
	#or, you could use the os_family() function and set up your os list
	}

	for my $port ($host->udp_ports())
	{ #now for UDP
	print OUT $host->addr().','.
	          $port.','.
	          $host->udp_port_state($port).','.
	          'udp,'.
	          $host->udp_service_name($port).','.
	          $host->udp_service_product($port).','.
	          $host->udp_service_version($port).','.
	          $host->udp_service_extrainfo($port).','.
	          $host->os_family()."\n";
	print STDOUT $host->addr().','.
	          $port.','.
	          $host->udp_port_state($port).','.
	          'udp,'.
	          $host->udp_service_name($port).','.
	          $host->udp_service_product($port).','.
	          $host->udp_service_version($port).','.
	          $host->udp_service_extrainfo($port).','.
	          $host->os_family()."\n";
	#tcp_service_name(portnumber) returns the service name running on that TCP port
	#you could, instead use os_class if available (available in Nmap::Parser::XML 0.64 and later
	#or, you could use the os_family() function and set up your os list
	}

}
close OUT;
print "\n\nOutput file generated: $OUT\n";
exit;


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


sub run_nmap_scan {
my @ips = grep {/(?:\d+\.){3}\d+/} @_;
my $NMAP;
	my $cmd;
	if($G{fast}){
	print "FastScan enabled\n" if($G{verbose} > 0 && $G{fast});
	$cmd = join ' ', (FAST_CMD, @ips);
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

port_info - quickly scans multiple hosts to determine port information

=head1 SYNOPSIS

 port_info.pl [OPTS] <IP_ADDR> [<IP.ADDR> ...]

=head1 DESCRIPTION

This script uses the nmap security scanner with the Nmap::Parser::XML module
in order to run a quick PING sweep against specific hosts. It takes in a nmap
xml file and outputs onto STDOUT and a file the all the ports that were scanned
and found by nmap, their different states and services -- all in a comma
delimited output

=head1 OPTIONS

These options are passes as command line parameters.

=over 4

=item B<-i nmapscan.xml>

Runs the script using the given xml file (which is nmap xml scan data) instead
of actually running a scan against the given set of hosts. This is useful if
you only have the xml data on a given machine, and not nmap.

=item B<--fast>

Runs a fast (-F) nmap scan against the host.

=item B<-h,--help,-?>

Shows this help information.

=item B<-o outputfile.csv>

Changes the output filename of the comma delimited file that is produced by
the script.

=item B<-v>

This runs the script in verbose mode. The more times used, the more verbose
the script will be.

=back 4

=head1 OUTPUT EXAMPLE

These are ONLY examples of how the output would look like. It follows the
conventions of:

 (IP, PORT_ID, STATE, PROTO, SERVICE, PRODUCT, VERSION, EXTRA, OS_FAMILIES)

  127.0.0.1,22,filtered,tcp,ssh,OpenSSH,3.5p1,protocol 1.99,linux
  127.0.0.1,25,filtered,tcp,smtp,Sendmail,8,,linux
  127.0.0.1,111,open,udp,rpcbind,,,,linux
  127.0.0.1,937,closed,udp,unknown,,,,linux
  127.0.0.4,22,filtered,tcp,ssh,OpenSSH,3.5p1,protocol 1.99,
  127.0.0.6,22,open,tcp,ssh,OpenSSH,3.5p1,protocol 1.99,solaris,switch
  127.0.0.6,23,filtered,tcp,telnet,,,,solaris,switch
  127.0.0.6,80,open,tcp,http,,,,solaris,switch

The default output filename is: port_info_out.csv

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