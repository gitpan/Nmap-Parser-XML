use 5.004;
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
    ABSTRACT		=> 'Nmap parser for XML output scan data',
    AUTHOR		=> 'Anthony G Persaud <ironstar@iastate.edu>',
    clean		=> {FILES => "*.tar *.old"},
    PM_FILTER 		=> 'grep -v "^\\#"',
   # EXE_FILES   	=> [ map {"examples/$_/$_"} @programs], #soon
    NAME		=> 'Nmap::Parser::XML',
    PREREQ_PM		=> \%depends,
    VERSION_FROM	=> 'XML.pm' # finds $VERSION
	);


