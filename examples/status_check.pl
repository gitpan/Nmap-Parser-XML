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
use constant CMD1 => 'nmap -sP -v -v -v -oX - ';
use File::Spec;
use Getopt::Long;
use Pod::Usage;
use vars qw(%G);
Getopt::Long::Configure('bundling');

my $p = new Nmap::Parser::XML;

print "\nStatus Check\t".(scalar localtime)."\n",('-'x50),"\n\n";
GetOptions(
		'help|h|?'	=> \$G{helpme},
		'v+'		=> \$G{verbose},
		'i=s'		=> \$G{usefile},
) or (pod2usage(-exitstatus => 0, -verbose => 1));

if($G{helpme} || ($G{usefile} eq '' && scalar @ARGV == 0))
	{pod2usage(-exitstatus => 0, -verbose => 1)}

if($G{usefile} eq ''){$p = run_nmap_scan(@ARGV);}
else {
	#use the input file
	print 'Using InputFile: '.$G{usefile}."\n" if($G{verbose} > 0);
	if(not -e $G{usefile})
	{print STDERR "ERROR: File $G{usefile} does not exists!\n"; exit;}
	$p->parsefile($G{usefile});
	}

#printing active hosts
print "Active Hosts Scanned:\n";
for my $ip ($p->get_host_list('up')){print "\t$ip\n";}
print "\n";
#printing inactive hosts
print "Inactive Hosts Scanned:\n";
for my $ip ($p->get_host_list('down')){print "\t$ip\n";}


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
my @ips =  grep {/(?:\d+\.){3}\d+/} @_;
my $NMAP;
	my $cmd = join ' ', (CMD1, @ips);
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

status_check - scans multiple hosts to determine their network status

=head1 SYNOPSIS

 status_check.pl [OPTS] <IP_ADDR> [<IP.ADDR> ...]

=head1 DESCRIPTION

This script uses the nmap security scanner with the Nmap::Parser::XML module
in order to run a quick PING sweep against specific hosts. It will then inform
of which hosts were active (up) and inactive (down).

=head1 OPTIONS

These options are passed as command line parameters.

=over 4

=item B<-i nmapscan.xml>

Runs the script using the given xml file (which is nmap xml scan data) instead
of actually running a scan against the given set of hosts. This is useful if
you only have the xml data on a given machine, and not nmap.

=item B<-h,--help,-?>

Shows this help information.

=item B<-v>

This runs the script in verbose mode. The more times used, the more verbose
the script will be.

=back 4

=head1 OUTPUT EXAMPLE

These are ONLY examples of how the output would look like.

  Status Check
  -------------------------------------------

  Active Hosts Scanned:
          127.0.0.5
          127.0.0.6
          127.0.0.2
          127.0.0.1
          127.0.0.4

  Inactive Hosts Scanned:
          127.0.0.3
          192.168.0.1
          192.168.0.2
          192.168.2.4


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
