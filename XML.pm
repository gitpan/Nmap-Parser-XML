package Nmap::Parser::XML;

################################################################################
##			Nmap::Parser::XML				      ##
################################################################################

use strict;
require 5.004;
use XML::Twig;
use vars qw($S %H %OS_LIST %F $DEBUG %R);
use constant IGNORE_ADDPORT => 1;


our $VERSION = '0.68';

sub new {

my ($class,$self) = shift;
$class = ref($class) || $class;

$$self{twig}  = new XML::Twig(
	start_tag_handlers 	=>
			{nmaprun => \&_nmaprun_hdlr},

	twig_roots 		=> {
		scaninfo => \&_scaninfo_hdlr,
		finished => \&_finished_hdlr,
		host 	 => \&_host_hdlr,
				},
	ignore_elts 	=> {
		addport 	=> IGNORE_ADDPORT,
		}

		);

#Default Filter Values
reset_filters();

%OS_LIST = (
	linux 	=> [qw(linux mandrake redhat slackware)],
	mac 	=> [qw(mac osx)],
	solaris => [qw(solaris sparc sun)],
	switch 	=> [qw(ethernet cisco netscout router switch bridge)],
	unix 	=> [qw(unix hp-ux hpux bsd immunix aix)],
	wap     => [qw(wireless wap)],
	win  	=> [qw(win microsoft workgroup)]
	    );

bless ($self,$class);
return $self;
}

################################################################################
##			PRE-PARSE METHODS				      ##
################################################################################
sub set_osfamily_list {
my $self = shift;my $list = shift;
%OS_LIST = %{$list};return \%OS_LIST;
}

sub get_osfamily_list {return \%OS_LIST;}

sub parse_filters {
my $self = shift;
my $filters = shift;
my $state;
grep {$F{lc($_)} = $filters->{$_} } keys %$filters;

$$self{twig}->setIgnoreEltsHandlers({
	'addport'	=> IGNORE_ADDPORT,
	'extraports'	=> ($F{extraports} ? undef : 1),
	'ports' 	=> ($F{portinfo} ? undef : 1),
	'tcpsequence' 	=> ($F{sequences} ? undef : 1),
	'ipidsequence' 	=> ($F{sequences} ? undef : 1),
	'tcptssequence' => ($F{sequences} ? undef : 1),
	'uptime' 	=> ($F{uptime} ? undef : 1),
	'scaninfo' 	=> ($F{scaninfo} ? undef : 1),
	'finished' 	=> ($F{scaninfo} ? undef : 1),
	});

return \%F;

}

sub reset_filters {
%F = (
	osfamily 	=> 1,
	scaninfo	=> 1,
	only_active 	=> 0,
	sequences 	=> 1,
	portinfo	=> 1,
	uptime		=> 1,
	extraports	=> 1,
	);


$_[0]->{twig}->setIgnoreEltsHandlers({
	addport 	=> IGNORE_ADDPORT,
	}) if(ref($_[0]) eq __PACKAGE__);


return \%F;

}


sub register_host_callback {
	my $self = shift;
	$R{host_callback_ref} = shift;
	if(ref($R{host_callback_ref}) eq 'CODE'){$R{host_callback_register} = 1;}
	else {
	die 'The callback parameter does not seem to be a code reference!';
	$R{host_callback_register} = undef;}
	return $R{host_callback_register};
	}

sub reset_host_callback {$R{host_callback_ref} = $R{host_callback_register}=undef;}

################################################################################
##			PARSE METHODS					      ##
################################################################################
sub parse {%H =();$S = undef;shift->{twig}->parse(@_);}
sub parsefile {%H=();$S = undef;shift->{twig}->parsefile(@_);}
sub safe_parse {%H=();$S = undef;shift->{twig}->safe_parse(@_);}
sub safe_parsefile {%H=();$S = undef;shift->{twig}->safe_parsefile(@_);}
sub clean {%H = ();$S = undef;$_[0]->{twig}->purge;return $_[0];}

################################################################################
##			POST-PARSE METHODS				      ##
################################################################################

sub get_host_list {my $status = lc($_[1]);
if($status eq 'up' || $status eq 'down')
{return (grep {($H{$_}{status} eq $status)}(keys %H))};
return (keys %H);
}
sub get_host {shift if(ref($_[0]) eq __PACKAGE__);return $H{$_[0]};}
sub del_host {shift if(ref($_[0]) eq __PACKAGE__);delete $H{$_[0]};}
sub get_host_objects {return values (%H);}

sub filter_by_osfamily {
my $self = shift;
my @keywords = @_;
my @os_matched_ips = ();
for my $addr (keys %H)
{
	my $os = $H{$addr}{os}{osfamily_names};
	next unless(defined($os) && ($os ne '') );
	if(scalar (grep {defined($_) &&  ($os =~ m/$_/)} @keywords))
	{push @os_matched_ips, $addr;}

}
return @os_matched_ips;

}

sub filter_by_status {
my $self= shift;
my $status = lc(shift);
$status = 'up' if($status ne 'up' && $status ne 'down');
return (grep {$H{$_}{status} eq $status} (keys %H));
}


sub get_scaninfo {return $S;}


################################################################################
##			PRIVATE TWIG HANDLERS				      ##
################################################################################

sub _scaninfo_hdlr {
my ($twig,$scan) = @_;
my ($type,$proto,$num) = ($scan->{'att'}->{'type'},$scan->{'att'}->{'protocol'},
$scan->{'att'}->{'numservices'});
if(defined($type)){$S->{type}{$type} = $proto;$S->{numservices}{$type} = $num;}
$twig->purge;}


sub _nmaprun_hdlr {#Last tag in an nmap output
my ($twig,$host) = @_;
unless($F{scaninfo}){return;}
$S->{start_time} = $host->{'att'}->{'start'};
$S->{nmap_version} = $host->{'att'}->{'version'};
$S->{args} = $host->{'att'}->{'args'};
$S = Nmap::Parser::XML::ScanInfo->new($S);

$twig->purge;
}


sub _finished_hdlr {my ($twig,$host) = @_;$S->{finish_time} =
$host->{'att'}->{'time'};$twig->purge;}


sub _host_hdlr {
my($twig, $host)= @_; # handlers are always called with those 2 arguments
my ($addr,$tmp);
    if(not defined($host)){return undef;}
    $tmp        = $host->first_child('address');         # get the element text
    if(not defined $tmp){return undef;}
    $addr = $tmp->{'att'}->{'addr'};
    if(!defined($addr) || $addr eq ''){return undef;}
    $H{$addr}{addr} = $addr;
    $H{$addr}{addrtype} = $tmp->{'att'}->{'addrtype'};
    $tmp = $host->first_child('hostnames');
    @{$H{$addr}{hostnames}} = _hostnames_hdlr($tmp,$addr) if(defined ($tmp = $host->first_child('hostnames')));
    $H{$addr}{status} = $host->first_child('status')->att('state');
    if($H{$addr}{status} eq 'down')
    {	$twig->purge;
	if($F{only_active}){delete $H{$addr};}
    	else { $H{$addr} = Nmap::Parser::XML::Host->new($H{$addr});}
    }
    else {

	    $H{$addr}{ports} = _port_hdlr($host,$addr) if($F{portinfo});
	    $H{$addr}{os} = _os_hdlr($host,$addr);
	    $H{$addr}{uptime} = _uptime_hdlr($host,$addr) if($F{uptime});

    	if($F{sequences})
	{
	    $H{$addr}{tcpsequence} = _tcpsequence($host,$addr);
	    $H{$addr}{ipidsequence} = _ipidsequence($host,$addr);
	    $H{$addr}{tcptssequence} = _tcptssequence($host,$addr);
	}

    	$H{$addr} = Nmap::Parser::XML::Host->new($H{$addr});
    }

    if($R{host_callback_register})
    { &{$R{host_callback_ref}}($H{$addr}); delete $H{$addr};}

    $twig->purge;                                      # purges the twig

}

sub _port_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
$tmp = $host->first_child('ports');
unless(defined $tmp){return undef;}

#EXTRAPORTS STUFF
my $extraports = $tmp->first_child('extraports');
if(defined $extraports && $extraports ne ''){
$H{$addr}{ports}{extraports}{state} = $extraports->{'att'}->{'state'};
$H{$addr}{ports}{extraports}{count} = $extraports->{'att'}->{'count'};
}

#PORT STUFF
@list= $tmp->children('port');
for my $p (@list){
my $proto = $p->{'att'}->{'protocol'};
my $portid = $p->{'att'}->{'portid'};
if(defined($proto && $portid)){$H{$addr}{ports}{$proto}{$portid} = _service_hdlr($host,$addr,$p);}
my $state = $p->first_child('state');
if(defined($state) && $state ne '')
{$H{$addr}{ports}{$proto}{$portid}{'state'} = $state->{'att'}->{'state'} || 'closed';}

}

return $H{$addr}{ports};
}



sub _service_hdlr {
my ($host,$addr,$p) = @_;
my $tmp;
my $s = $p->first_child('service[@name]');
$tmp->{service_name} = 'unknown';

if(defined $s){
$tmp->{service_proto} = '';
$tmp->{service_name} = $s->{'att'}->{'name'};
$tmp->{service_proto} = $s->{'att'}->{'proto'} if($s->{'att'}->{'proto'});
$tmp->{service_rpcnum} = $s->{'att'}->{'rpcnum'} if($tmp->{service_proto} eq 'rpc');
}

return $tmp;

}

sub _os_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my ($host,$addr) = (shift,shift);
my ($tmp,@list);
if(defined(my $os_list = $host->first_child('os'))){
    $tmp = $os_list->first_child("portused[\@state='open']");
    $H{$addr}{os}{portused}{'open'} = $tmp->{'att'}->{'portid'} if(defined $tmp);
    $tmp = $os_list->first_child("portused[\@state='closed']");
    $H{$addr}{os}{portused}{'closed'} = $tmp->{'att'}->{'portid'} if(defined $tmp);


    for my $o ($os_list->children('osmatch')){push @list, $o->{'att'}->{'name'};  }
    @{$H{$addr}{os}{names}} = @list;

    $H{$addr}{os}{osfamily_names} = _match_os(@list) if($F{osfamily});

    @list = ();
    for my $o ($os_list->children('osclass'))
    {push @list, [$o->{'att'}->{'osfamily'},$o->{'att'}->{'osgen'},$o->{'att'}->{'vendor'},$o->{'att'}->{'type'}];}
    @{$H{$addr}{os}{osclass}} = @list;

    }

    return $H{$addr}{os};

}


sub _uptime_hdlr {
my ($host,$addr) = (shift,shift);
my $uptime = $host->first_child('uptime');
my $hash;
if(defined $uptime){
	$hash->{seconds} = $uptime->{'att'}->{'seconds'};
	$hash->{lastboot} = $uptime->{'att'}->{'lastboot'};
}
return $hash;
}


sub _hostnames_hdlr {
shift if(ref($_[0]) eq __PACKAGE__);
my $hostnames = shift;
my $addr = shift;
my @names;
for my $n ($hostnames->children('hostname')) {push @names, $n->{'att'}->{'name'};}
return @names if(wantarray);
return \@names;

}

sub _tcpsequence {
my ($host,$addr) = (shift,shift);
my $temp;
my $seq = $host->first_child('tcpsequence');
unless($seq){return undef;}

return [$seq->{'att'}->{'class'},$seq->{'att'}->{'values'},$seq->{'att'}->{'index'}];

}

sub _ipidsequence {
my ($host,$addr) = (shift,shift);
my $temp;
my $seq = $host->first_child('ipidsequence');
unless($seq){return undef;}
return [$seq->{'att'}->{'class'},$seq->{'att'}->{'values'}];

}


sub _tcptssequence {
my ($host,$addr) = (shift,shift);
my $temp;
my $seq = $host->first_child('tcptssequence');
unless($seq){return undef;}
return [$seq->{'att'}->{'class'},$seq->{'att'}->{'values'}];
}

sub _match_os {

shift if(ref($_[0]) eq __PACKAGE__);
my $os_string = lc(join '', @_);
$os_string =~ s/\s|\n//g;
my @matches;
unless(keys %OS_LIST){return undef;}
for my $os_family (keys %OS_LIST){
	my @keywords = @{$OS_LIST{$os_family}};
	for my $keyword (@keywords){
		if($os_string =~ /$keyword/){
			push @matches, $os_family;}
	}


}
if(scalar @matches){return (join ',', sort keys %{ {map {$_,1} @matches} } );}
return 'other';

}


################################################################################
##			Nmap::Parser::XML::ScanInfo			      ##
################################################################################

package Nmap::Parser::XML::ScanInfo;

sub new {
my $class = shift;
$class = ref($class) || $class;
my $self =  shift || {};
bless ($self,$class);
return $self;
}

sub num_of_services {
if($_[1] ne ''){return $_[0]->{numservices}{$_[1]};}
else {my $total = 0;for (values %{$_[0]->{numservices}}){$total +=$_;}
return $total;}
}
sub finish_time {return $_[0]->{finish_time};}
sub nmap_version {return $_[0]->{nmap_version};}
sub args {return $_[0]->{args};}
sub start_time {return $_[0]->{start_time};}
sub scan_types {(wantarray) ? 	return (keys %{$_[0]->{type}}) :
				return scalar(keys %{$_[0]->{type}});}
sub proto_of_scan_type {return $_[0]->{type}{$_[1]};}


################################################################################
##			Nmap::Parser::XML::Host				      ##
################################################################################

package Nmap::Parser::XML::Host;


sub new {
my ($class,$self) = (shift);
$class = ref($class) || $class;
$self = shift || {};
bless ($self,$class);
return $self;
}

sub status {return $_[0]->{status};}
sub addr {return $_[0]->{addr};}
sub addrtype {return $_[0]->{addrtype};}
sub hostname  { return ${$_[0]->{hostnames}}[0];   } #returns the first hostname
sub hostnames {($_[1]) ? 	return @{$_[0]->{hostnames}}[ $_[1] - 1] :
				return @{$_[0]->{hostnames}};}

sub extraports_state {return $_[0]->{ports}{extraports}{state};}
sub extraports_count {return $_[0]->{ports}{extraports}{count};}


sub _get_ports {
my $proto = pop;
my $param = lc($_[1]);

if($param eq 'closed' || $param eq 'filtered' || $param eq 'open')
{
	my @matched_ports;
	for my $p (keys %{ $_[0]->{'ports'}{$proto}   })
	{
		if($_[0]->{ports}{$proto}{$p}{state} eq $param)
			{push @matched_ports, $p;}
	}
	return sort {$a <=> $b} @matched_ports;
}
else {return sort {$a <=> $b} (keys %{$_[0]->{ports}{$proto}});}

}

sub _get_port_state {
my $proto = pop;
my $param = lc($_[1]);
	if(exists ${$_[0]}{ports}{$proto}{$param})
		{return $_[0]->{ports}{$proto}{$param}{state};}
	elsif($Nmap::Parser::XML::F{portinfo} == 0)
		{return undef;}
	else {return 'closed';}
}

#changed this to use _get_ports since it was similar code
sub tcp_ports { return _get_ports(@_,'tcp');}
sub udp_ports { return _get_ports(@_,'udp');}

sub tcp_ports_count {return scalar(keys %{$_[0]->{ports}{tcp}})}
sub udp_ports_count {return scalar(keys %{$_[0]->{ports}{udp}})}

sub tcp_port_state {return _get_port_state(@_,'tcp');}
sub udp_port_state {return _get_port_state(@_,'udp');}

sub tcp_service_name {return $_[0]->{ports}{tcp}{$_[1]}{service_name};}
sub udp_service_name {return $_[0]->{ports}{udp}{$_[1]}{service_name};}

sub tcp_service_proto {return $_[0]->{ports}{tcp}{$_[1]}{service_proto};}
sub udp_service_proto {return $_[0]->{ports}{udp}{$_[1]}{service_proto};}

sub tcp_service_rpcnum {return $_[0]->{ports}{tcp}{$_[1]}{service_rpcnum};}
sub udp_service_rpcnum {return $_[0]->{ports}{udp}{$_[1]}{service_rpcnum};}

sub os_match {return @{$_[0]->{os}{names}}[0];}
sub os_matches {($_[1]) ? 	return @{$_[0]->{os}{names}}[ $_[1] - 1 ] :
				return (@{$_[0]->{os}{names}});}

sub os_port_used {
$_[1] ||= 'open';
if(lc($_[1]) eq 'closed'){return $_[0]->{os}{portused}{'closed'};}
elsif(lc($_[1]) eq 'open'){  return $_[0]->{os}{portused}{'open'};}
}

sub os_family {(wantarray) ? 	return (split ',', $_[0]->{os}{osfamily_names}) :
				return $_[0]->{os}{osfamily_names};}

sub os_class {
if($_[1] eq ''){return @{@{$_[0]->{os}{osclass}}[0]}}
elsif(lc($_[1]) eq 'total'){return scalar @{$_[0]->{os}{osclass}};}
elsif($_[1] ne ''){return @{@{$_[0]->{os}{osclass}}[$_[1] - 1]};}

	}

sub tcpsequence {return @{$_[0]->{tcpsequence}}    if($_[0]->{tcpsequence});}
sub ipidsequence {return @{$_[0]->{ipidsequence}}  if($_[0]->{ipidsequence});}
sub tcptssequence {return @{$_[0]->{tcptssequence}} if($_[0]->{tcptssequence});}

sub uptime_seconds {return $_[0]->{uptime}{seconds};}
sub uptime_lastboot {return $_[0]->{uptime}{lastboot};}

1;

__END__

=pod

=head1 NAME

Nmap::Parser::XML - nmap parser for xml scan data using perl.

=head1 SYNOPSIS

  use Nmap::Parser::XML;

 	#PARSING
  my $npx = new Nmap::Parser::XML;
  $npx->parse($fh); #filehandle or nmap xml output string
  #or $npx->parsefile('nmap_output.xml') for files

 	#GETTING SCAN INFORMATION

  print "Scan Information:\n";
  $si = $npx->get_scaninfo();
  #Now I can get scan information by calling methods
  print
  'Number of services scanned: '.$si->num_of_services()."\n",
  'Start Time: '.$si->start_time()."\n",
  'Scan Types: ',(join ' ',$si->scan_types())."\n";

 	#GETTING HOST INFORMATION

   print "Hosts scanned:\n";
   for my $host_obj ($npx->get_host_objects()){
   print
  'Hostname  : '.$host_obj->hostname()."\n",
  'Address   : '.$host_obj->addr()."\n",
  'OS match  : '.$host_obj->os_match()."\n",
  'Open Ports: '.(join ',',$host_obj->tcp_ports('open'))."\n";
  	#... you get the idea...
   }

  $p->clean(); #frees memory
  # ... do other stuff if you want ...

=head1 DESCRIPTION

This is an stand-alone output parser for nmap XML reports. This uses the XML::Twig library
which is fast and memory efficient. This module does not do a nmap scan
(See Nmap::Scanner for that functionality). It either can parse a nmap xml file,
or it can take a filehandle that is piped from a current nmap running scan using '-oX -'
switch.This module, in the authors opinion, is easier to use for basic information
gathering of hosts.

This module is meant to be a balance of easy of use and efficiency. (more ease
of use). I have added filtering capabilities and use various options on the twig
library in order to incrase parsing speed and save on memory usage. If you need
more information from an nmap xml-output that is not available in the release,
please send your request. (see below).

=head2 OVERVIEW

Using this module is very simple. (hopefully).

=over 4

=item I<Set your Options>

You first set any filters you want on the information you will parse. This
is optional, but if you wish the parser to be more efficient, don't parse
information you don't need. Other options (os_family) can be
set also. (See Pre-Parse methods)

Example, if you only want to retain the information of the hosts that nmap
found to be up (active), then set the filter:

 $npx->parse_filters({only_active => 1});

Usually you won't have much information about hosts that are down from nmap
anyways.

=item I<Run the parser>

Parse the info. You use $npx->parse() or $npx->parsefile(), to parse the nmap xml
information. This information is parsed and constructed internally.

=item I<Get the Scan Info>

Use the $si = $npx->get_scaninfo() to obtain the
Nmap::Parser::XML::ScanInfo object. Then you can call any of the
ScanInfo methods on this object to retrieve the information. See
Nmap::Parser::XML::ScanInfo below.

=item I<Get the Host Info>

Use the $npx->get_host($addr) to obtain the Nmap::Parser::XML::Host object of the
current address. Using this object you can call any methods in the Host object
to retrieve the information that nmap obtained from this scan.

 $npx->get_host($ip_addr);

You can use any of the other methods to filter or obtain
different lists.

 	#returns all ip addresses that were scanned
 $npx->get_host_list()

 	#returns all ip addresses that have osfamily = $os
 $npx->filter_by_osfamily($os)
	 #See get_os_list() and set_os_list()
	 #etc. (see other methods)

	#returns all host objects from the information parsed.
	#All are Nmap::Parser::XML::Host objects
 $npx->get_host_objects()


=item I<Clean up>

This is semi-optional. When files are not that long, this is optional.
If you are in a situation with memory constraints and are dealing with large
nmap xml-output files, this little effort helps. After you are done with everything, you should do a $npx->clean()
to free up the memory used by maintaining the scan and hosts information
from the scan. A much more efficient way to do is, once you are done using a
host object, delete it.

 		#Getting all IP addresses parsed
 for my $host ($npx->get_host_list())
 	{	#Getting the host object for that address
	my $h = $npx->get_host($host);
		#Calling methods on that object
	print "Addr: $host  OS: ".$h->os_match()."\n";
	$npx->del_host($host); #frees memory
	}

	#Or when you are done with everything use $npx->clean()
Or you could skip the $npx->del_host(), and after you are done, perform a
$npx->clean() which resets all the internal trees. Of course there are much
better ways to clean-up (using perl idioms).

=back

=head1 METHODS

=head2 Pre-Parsing Methods

=over 4

=item B<new()>

Creates a new Nmap::Parser::XML object with default handlers and default
osfamily list. In this document the current Nmap::Parser::XML object will be
referred as B<$npx>.

 my $npx = new Nmap::Parser::XML; #NPX = Nmap Parser XML for those curious

=item B<set_osfamily_list($hashref)>

Decides what is the osfamily name of the given system.

Takes in a hash refernce that referes to pairs of osfamily names to their
keyword list. Shown here is the default. Calling this method will overwrite the
whole list, not append to it. Use C<get_osfamily_list()> first to get the current
listing.

  $npx->set_osfamily_list({
	linux 	=> [qw(linux mandrake redhat slackware)],
	mac 	=> [qw(mac osx)],
	solaris => [qw(solaris sparc sun)],
	switch 	=> [qw(ethernet cisco netscout router switch bridge)],
	unix 	=> [qw(unix hp-ux hpux bsd immunix aix)],
	wap     => [qw(wireless wap)],
	win  	=> [qw(win microsoft workgroup)]
	    });

example: osfamily_name = solaris if the os string being matched
matches (solaris, sparc or sunos) keywords

The reason for having this seprately that relying on the 'osclass' tag in the
xml output is that the 'osclass' tag is not generated all the time. Usually
new versions of nmap will generate the 'osclass' tags. These will be available
through the Nmap::Parser::XML::Host methods. (See below).

=item B<get_osfamily_list()>

Returns a hashre containing the current osfaimly names (keys) and
an arrayref pointing to the list of corresponding keywords (values).
See C<set_osfamily_list()> for an example.

=item B<parse_filters($hashref)>

This function takes a hash reference that will set the corresponding filters
when parsing the xml information. All filter names passed will be treated
as case-insensitive. I<NOTE: This version of the parser will ignore the 'addport'
tag in the xml file. If you feel the need for this tag. Send your feedback>

 $npx->parse_filters({
 	osfamily 	=> 1, #same as any variation. Ex: osfaMiLy
 	only_active	=> 0   #same here
 		});

=item I<OSFAMILY>

If set to true, (the default), it will match the OS guessed by nmap with a
osfamily name that is given in the OS list. See set_osfamily_list(). If
false, it will disable this matching (a bit of speed up in parsing).

=item I<ONLY_ACTIVE>

If set to true, it will ignore hosts that nmap found to be in state 'down'.
If set to perl-wise false, it will parse all the hosts. This is the default.
Note that if you do not place this filter, it will parse and store (in memory)
hosts that do not have much information. So calling a Nmap::Parser::XML::Host
method on one of these hosts that were 'down', will return undef.

=item I<SEQUENCES>

If set to true, parses the tcpsequence, ipidsequence and tcptssequence
information. This is the default.

=item I<PORTINFO>

If set to true, parses the port information. (You usually want this enabled).
This is the default.

=item I<SCANINFO>

If set to true, parses the scan information. This includes the 'scaninfo',
'nmaprun' and 'finished' tags. This is set to true by default. If you don't
care about the scan information of the file, then turn this off to enhance speed
and memory usage.

=item I<UPTIME>

If set to true, parses the uptime information (lastboot, uptime-seconds..etc).
This is the default.

=item B<reset_filters()>

Resets the value of the filters to the default values:

 osfamily 	=> 1
 scaninfo	=> 1
 only_active 	=> 0
 sequences 	=> 1
 portinfo	=> 1
 scaninfo	=> 1
 uptime		=> 1


=item B<register_host_callback>
I<Experimental - interface might change in future releases>

Sets a callback function, (which will be called) whenever a host is found. The
callback defined will receive as arguments the current Nmap::Parser::XML::Host
that was just parsed. After the callback returns (back to Nmap::Parser::XML to
keep on parsing other hosts), that current host will be deleted (so you don't
have to delete it yourself). This saves a lot of memory since after you perform
the actions you wish to perform on the Nmap::Parser::XML::Host object you currently
have, it gets deleted from the tree.

 $npx->register_host_callback(\&host_handler);

 sub host_handler {
 my $host_obj = shift; #an instance of Nmap::Parser::XML::Host (for current)

 ... do stuff with $host_obj ... (see Nmap::Parser::XML::Host doc)

 return; # $host_obj will be deleted (similar to del_host()) method

 }

=item B<reset_host_callback>
I<Experimental - interface might change in future releases>

Resets the host callback function, and does normal parsing.

=back

=head2 Parse Methods

=over 4

=item B<parse($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::parse().

This method is inherited from XML::Parser.  The "SOURCE" parameter should
either be a string containing the whole XML document, or it should be
an open "IO::Handle". Constructor options to "XML::Parser::Expat" given as
keyword-value pairs may follow the"SOURCE" parameter. These override, for this
call, any options or attributes passed through from the XML::Parser instance.

A die call is thrown if a parse error occurs. Otherwise it will return
the twig built by the parse. Use "safe_parse" if you want the
parsing to return even when an error occurs.

=item B<parsefile($filename [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::parsefile().

This method is inherited from XML::Parser. Open
"$filename" for reading, then call "parse" with the open
handle. The file is closed no matter how "parse" returns.

A die call is thrown if a parse error occurs. Otherwise it willreturn
the twig built by the parse. Use "safe_parsefile" if you want
the parsing to return even when an error occurs.

=item B<safe_parse($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::safe_parse().

This method is similar to "parse" except that it wraps the parsing
in an "eval" block. It returns the twig on success and 0 on failure (the twig
object also contains the parsed twig). $@ contains the error message on failure.

Note that the parsing still stops as soon as an error is detected,
there is no way to keep going after an error.

=item B<safe_parsefile($source [, opt =E<gt> opt_value [...]])>

Same as XML::Twig::safe_parsefile().

This method is similar to "parsefile" except that it wraps the
parsing in an "eval" block. It returns the twig on success and 0 on
failure (the twig object also contains the parsed twig) . $@ contains the error
message on failure

Note that the parsing still stops as soon as an error is detected,
there is no way to keep going after an error.

=item B<clean()>

Frees up memory by cleaning the current tree hashes and purging the current
information in the XML::Twig object. Returns the Nmap::Parser::XML object.

=back

=head2 Post-Parse Methods

=over 4

=item B<get_host_list([$status])>

Returns all the ip addresses that were run in the nmap scan.
$status is optional and can be either 'up' or 'down'. If $status is
given, then only IP addresses that have that corresponding state will
be returned. Example: setting $status = 'up', then will return all IP
addresses that were found to be up. (network talk for active)

=item B<get_host($ip_addr)>

Returns the complete host object of the corresponding IP address.

=item B<del_host($ip_addr)>

Deletes the corresponding host object from the main tree. (Frees up
memory of unwanted host structures).

=item B<get_host_objects()>

Returns all the host objects of all the IP addresses that nmap had run against.
See L<Nmap::Parser::XML::Host>.

=item B<filter_by_osfamily(@osfamily_names)>

This returns all the IP addresses that have match any of the keywords in
@osfamily_names that is set in their osfamily_names field. See os_list()
for example on osfamily_name. This makes it easier to sift through the
lists of IP if you are trying to split up IP addresses
depending on platform (window and unix machines for example).

=item B<filter_by_status($status)>

This returns an array of hosts addresses that are in the $status state.
$status can be either 'up' or 'down'. Default is 'up'.

=item B<get_scaninfo()>

Returns the the current Nmap::Parser::XML::ScanInfo.
Methods can be called on this object to retrieve information
about the parsed scan. See L<Nmap::Parser::XML::ScanInfo> below.

=back

=head2 Nmap::Parser::XML::ScanInfo

The scaninfo object. This package contains methods to easily access
all the parameters and values of the Nmap scan information ran by the
currently parsed xml file or filehandle.

 $si = $npx->get_scaninfo();
 print 	'Nmap Version: '.$si->nmap_version()."\n",
 	'Num of Scan Types: '.(join ',', $si->scan_types() )."\n",
 	'Total time: '.($si->finish_time() - $si->start_time()).' seconds';
 	#... you get the idea...

=over 4

=item B<num_of_services([$scan_type])>;

If given a corresponding scan type, it returns the number of services
that was scan by nmap for that scan type. If $scan_type is omitted,
then num_of_services() returns the total number of services scan by all
scan_types.

=item B<start_time()>

Returns the start time of the nmap scan.

=item B<finish_time()>

Returns the finish time of the nmap scan.

=item B<nmap_version()>

Returns the version of nmap that ran.

=item B<args()>

Returns the command line parameters that were run with nmap

=item B<scan_types()>

In list context, returns an array containing the names of the scan types
that were selected. In scalar context, returns the total number of scan types
that were selected.

=item B<proto_of_scan_type($scan_type)>

Returns the protocol of the specific scan type.

=back

=head2 Nmap::Parser::XML::Host

The host object. This package contains methods to easily access the information
of a host that was scanned.

  $host_obj = Nmap::Parser::XML->get_host($ip_addr);
   #Now I can get information about this host whose ip = $ip_addr
   print
  'Hostname: '.$host_obj->hostnames(1),"\n",
  'Address:  '.$host_obj->addr()."\n",
  'OS match: '.$host_obj->os_match()."\n",
  'Last Reboot: '.($host_obj->uptime_lastboot,"\n";
  #... you get the idea...

If you would like for me to add more advanced information (such as
TCP Sequences), let me know.

=over 4

=item B<status()>

Returns the status of the host system. Either 'up' or 'down'

=item B<addr()>

Returns the IP address of the system

=item B<addrtype()>

Returns the address type of the IP address returned
by addr(). Ex. 'ipv4'

=item B<hostname()>

Returns the first hostname found of the current host object. This is a short-cut
to using hostnames(1).

 $host_obj->hostname() eq $host_obj->hostnames(1) #Always true

=item B<hostnames($number)>

If $number is omitted (or false), returns an array containing all of
the host names. If $number is given, then returns the host name in that
particular index. The index starts at 1.

 $host_obj->hostnames();  #returns an array containing the hostnames found
 $host_obj->hostnames(1); #returns the 1st hostname found
 $host_obj->hostnames(4); #returns the 4th. (you get the idea..)

=item B<extraports_state()>

Returns the state of the extra ports found by nmap. I<(The 'state' attribute
in the extraports tag)>.

=item B<extraports_count()>

Returns the number of extra ports that nmap found to be in a given state. I<(The
'count' attribute in the extraports tag)>.

=item B<tcp_ports([$state])>, B<udp_ports([[$state]])>

Returns an sorted array containing the tcp/udp ports that were scanned. If the
optional 'state' paramter is passed, it will only return the ports that nmap
found to be in that state.The value of $state can either be 'closed', 'filtered'
 or 'open'.  I<NOTE: If you used a parsing filter such as setting portinfo => 0,
then all ports will return undef.>

 my @ports = $host_obj->tcp_ports; #all ports
 my $port = pop @ports;

 if($host_obj->tcp_port_state($port) ne 'closed'){

	 $host_obj->tcp_service_name($port);  #ex: rpcbind
	 $host_obj->tcp_service_proto($port); #ex: rpc (may not be defined)
	 $host_obj->tcp_service_rpcnum($port);#ex: 100000 (only if proto is rpc)
 }

Again, you could filter what ports you wish to receive:

 #it can be either 'filtered', 'closed' or 'open'

 my @filtered_ports = $host_obj->tcp_ports('filtered');
 my @open_ports = $host_obj->tcp_ports('open');

=item B<tcp_ports_count()>, B<udp_ports_count()>

Returns the number of tcp/udp ports found. This is a short-cut function (but more
efficient) to:

 scalar @{[$host->tcp_ports]} == $host->tcp_ports_count;

=item B<tcp_port_state($port)>, B<udp_port_state($port)>

Returns the state of the given tcp/udp port.

=item B<tcp_service_name($port)>, B<udp_service_name($port)>

Returns the name of the service running on the
given udp $port. (if any)

=item B<tcp_service_proto($port)>, B<udp_service_proto($port)>

Returns the protocol type of the given port. This can be tcp, udp, or rpc as
given by nmap.

=item B<tcp_service_rpcnum($port)>, B<udp_service_rpcnum($port)>

Returns the rpc number of the service on the given port. I<This value only
exists if the protocol on the given port was found to be RPC by nmap.>

=item B<os_match>

Same as os_matches(), except this is a short-cut function for obtaining the
first OS guess provided by nmap. The statements are equivalent:

 $host_obj->os_matches(1) eq $host_obj->os_match() #true

=item B<os_matches([$number])>

If $number is omitted, returns an array of possible matching os names.
If $number is given, then returns that index entry of possible os names.
The index starts at 1.

 $host_obj->os_matches();  #returns an array containing the os names found
 $host_obj->os_matches(1); #returns the 1st os name found
 $host_obj->os_matches(5); #returns the 5th. (you get the idea...)

=item B<os_port_used($state)>

Returns the port number that was used in determining the OS of the system.
If $state is set to 'open', then the port id that was used in state open is
returned. If $state is set to 'closed', then the port id that was used in state
closed is returned. (no kidding...). Default, the open port number is returned.

=item B<os_family()>

Returns the osfamily_name that was matched to the given host. This osfamily
value is determined by the list given in the *_osfamily_list() functions.

I<Note: see set_osfamily_list()>

=item B<os_class([$number])>
I<Experimental - interface might change in future releases>

Returns the os_family, os_generation and os_type that was guessed by nmap. The
os_class tag does not always appear in all nmap OS fingerprinting scans. This
appears in newer nmap versions. You should check to see if there are values to
this. If you want a customized (and sure) way of determining an os_family value
use the *_osfamily_list() functions to set them. These will determine what
os_family value to give depending on the osmatches recovered from the scan.

 ($os_family,$os_gen,$os_type) = $host_obj->os_class(); #returns the first set

There can be more than one os_class (different kernels of Linux for example).
In order to access these extra os_class information, you can pass an index
number to the function. If not number is given, the first os_class
information is returned. The index starts at 1.

  #returns the first set (same as passing no arguments)
 ($os_family,$os_gen,$os_vendor,$os_type) = $host_obj->os_class(1);

  #returns os_gen value only. Example: '2.4.x' if is a Linux 2.4.x kernel.
  $os_gen                      = ($host_obj->os_class())[2];# os_gen only

You can play with perl to get the values you want easily. Also, if argument
'total' is passed, it will return the total number os_class tags parsed for this
host.

I<Note: This tag is usually available in new versions of nmap. You can define
your own os_family customizing the os_family lists using the
Nmap::Parser::XML functions: set_osfamily_list() and get_osfamily_list().>

=item B<tcpsequence()>

Returns the tcpsequence information in the format:

 ($class,$values,$index) = $host_obj->tcpsequence();

=item B<ipidsequence()>

Returns the ipidsequence information in the format:

 ($class,$values) = $host_obj->ipidsequence();

=item B<tcptssequence()>

Returns the tcptssequence information in the format:

 ($class,$values) = $host_obj->tcptssequence();

=item B<uptime_seconds()>

Returns the number of seconds the host has been up (since boot).

=item B<uptime_lastboot()>

Returns the time and date the given host was last rebooted.

=back

=head1 ACKNOWLEDGEMENTS

Thanks to everyone who has inspired and have provided feedback to improve and
enhance this module: http://search.cpan.org/author/APERSAUD/Nmap-Parser-XML/

=head1 AUTHOR

Anthony G Persaud <ironstar@iastate.edu>

=head1 SEE ALSO

nmap, L<XML::Twig>

  http://www.insecure.org/nmap/
  http://www.xmltwig.com

=head1 COPYRIGHT

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

=cut
