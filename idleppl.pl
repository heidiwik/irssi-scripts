#!/usr/bin/perl
#
use strict;
use Irssi;

use vars qw($VERSION %IRSSI);
use Data::Dumper qw(Dumper);

$VERSION = "20191230";
%IRSSI = (
    authors     => "heidiwik",
    contact     => "",
    name        => "idlefriends",
    description => "Retrieves the idletime of friends. Chains whois and displays last seen",
    license     => "GPLv2",
    url         => "",
    changed     => "$VERSION",
    commands    => "idle"
);


our @_unsurveyed_nicks    = undef;
our $_target_server       = undef;


sub finished {
	  Irssi::signal_remove( 'redir nicks_left', 'nicks_left');
    @_unsurveyed_nicks = undef;
}


sub event_whois_idle {
  my ($empty, $name, $sec, $signon, $rest) = ( split / +/, $_[1], 5 );
	my $days  = int($sec/3600/24);
	my $hours = int(($sec%(3600*24))/3600);
	my $min   = int(($sec%3600)/60);
	my $secs  = int($sec%60);

  my $last_active = scalar localtime (time() - $sec);

  if (length($name) < 10) {
      $name = sprintf("%-10s",$name);
  }

  Irssi::print("$name is idle $days days $hours hours $min mins $secs secs. Last seen $last_active ", MSGLEVEL_CLIENTCRAP);

}

sub nicks_left
{
  my $server = $_target_server;
	my $nick   = pop @_unsurveyed_nicks;
#  Irssi::print Dumper(@_unsurveyed_nicks);

	if( !$nick  )
	{
  	finished();
		return;
	}


	# We chain WHOIS requests rather than dump the entire lot in a loop
	# so server_queue is not going to be full of whois response.
	#
	$server->redirect_event( 'whois', 1, $nick, 0, undef, {
			'event 317' => 'redir get_idle',  # idle
			'event 318' => 'redir nicks_left',  # end of whois
			'event 401' => 'redir nicks_left',  # no such nick
			''          => 'event empty'} );

	$server->send_raw( "WHOIS " . $nick . " " . $nick );

}

sub cmd_idlefriends {
    my ($nicks, $server, $witem) = @_;

    foreach (split(/\s+/, $nicks)) {
      push @_unsurveyed_nicks, $_;
    }

    $_target_server = $server;

    Irssi::signal_add( 'redir nicks_left', 'nicks_left' );
    nicks_left();
}

Irssi::signal_add('redir get_idle' => \&event_whois_idle);

Irssi::command_bind('idle', 'cmd_idlefriends');
