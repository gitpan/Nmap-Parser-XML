use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my %depends = (XML::Parser => 2.23,
              XML::Twig   => 3.09
              );

print "Checking for dependencies...\n\n";
for my $mod (sort keys %depends)
{
eval "require ".$mod;
if($@){print "[-] $mod NOT INSTALLED! -- please install\n";$error = 1;next;}
my $version =  eval eval '$'.$mod."::VERSION";

if($version < $depends{$mod}){print "[-] $mod version problem: cur $version < req $depends{$mod}.\n\tPlease update to $depends{$mod}\n";$error = 1;}
else {printf("%-15s : v%.2f\n",$mod,$version);}

}


WriteMakefile(
    'NAME'		=> 'Nmap::Parser::XML',
    'VERSION_FROM'	=> 'XML.pm', # finds $VERSION
    'PREREQ_PM'		=> \%depends,
    'ABSTRACT'		=> 'Nmap parser for XML output scan data',
    'AUTHOR'	       => 'Anthony G Persaud <ironstar@iastate.edu>'
	);


