use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Nmap::Parser::XML',
    'VERSION_FROM'	=> 'XML.pm', # finds $VERSION
    'PREREQ_PM'		=> {'XML::Twig' => 2.5}, # e.g., Module::Name => 1.1
    'ABSTRACT'		=> 'Simple nmap xml-output parser',
    'AUTHOR'	       => 'Anthony G Persaud <ironstar@iastate.edu>'
	);


