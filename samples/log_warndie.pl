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

use constant windows => ( $^O =~ /^MSWin(?:32|64)/ );

my $dispatcher = Log::Dispatch->new;
$dispatcher->add(Log::Dispatch::File->new(name => 'foo',
                                          min_level => 'debug',
					  filename => (windows
						       ? 'C:\\dispatcher.log'
						       : '/tmp/dispatcher.log')));

Log::WarnDie->dispatcher( $dispatcher );

my $s = Net::SFTP::Foreign->new(windows
				? ('salva@10.0.2.2',
				   ssh_cmd => 'C:\\Archivos de programa\\PuTTY\\plink.exe',
				   more => [qw(-pw foo)],
				)
				: ('localhost'));

$s->error and die "unable to connecte to remote host: " . $s->error;
print Dumper $s->ls('.', names_only => 1);


