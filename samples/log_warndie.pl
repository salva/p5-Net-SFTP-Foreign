#!/usr/bin/perl

use strict;
use warnings;
use Data::Dumper;

use Net::SFTP::Foreign;

use Log::WarnDie;
# Log::WarnDie is missing FILENO method, just patch it in...
sub Log::WarnDie::FILENO { 2 }

use Log::Dispatch;
use Log::Dispatch::File;

my $dispatcher = Log::Dispatch->new;
$dispatcher->add(Log::Dispatch::File->new(name => 'foo',
                                          min_level => 'debug',
                                          filename => "/tmp/dispatcher.log"));
Log::WarnDie->dispatcher( $dispatcher );

my $s = Net::SFTP::Foreign->new("localhost");
$s->error and die "unable to connecte to remote host: " . $s->error;
print Dumper $s->ls('.', names_only => 1);


