use 5.004;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

my %depends = (XML::Twig   => 3.09,
               Nmap::Parser => 0.7);

WriteMakefile(
    ABSTRACT		=> 'nmap parser for XML output scan data',
    AUTHOR		=> 'Anthony G Persaud <ironstar@iastate.edu>',
    clean		=> {FILES => "*.tar *.old pod2htm*"},
   # EXE_FILES   	=> [ map {"examples/$_/$_"} @programs], #soon
    NAME		=> 'Nmap::Parser::XML',
    PREREQ_PM		=> \%depends,
    VERSION_FROM	=> 'XML.pm' # finds $VERSION
	);


