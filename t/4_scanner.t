#!/usr/bin/perl



use strict;
use blib;
use File::Spec;
use Cwd;
use Test::More tests => 3;
use constant IP => '127.0.0.1';
use Nmap::Parser::XML;
no warnings;
use vars qw($t1 $t2);
$|=1;

my $p = new Nmap::Parser::XML;
my $nmap_exe = find_nmap();

SKIP: {
skip 'Nmap executable could not be found on PATH!',2 unless($nmap_exe ne '');
ok($nmap_exe, "Testing find_nmap()");
skip "OS does not like loopbacks",2 if(lc($^O) =~ /win|solaris|sunos/);
ok($p->parsescan($nmap_exe,'-sP', IP), "Testing parsescan()" );
is($p->get_host(IP)->addr(),IP, "Verifying information" );
}


sub find_nmap {

    my $exe_to_find = 'nmap';
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