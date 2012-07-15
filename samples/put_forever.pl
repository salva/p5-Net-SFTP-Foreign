#!/usr/bin/perl

use lib::glob 'Y:/g/perl/p5-*/lib';

use strict;
use warnings;
use 5.012;

use File::Basename;
use Net::SFTP::Foreign;

my $target = shift(@ARGV) // die "target missing";
@ARGV > 0 or die "file list missing";

my ($user, $password, $host) = $target =~ /^([^:]+):([^\@]+)\@(.*)$/ or die "invalid target";

my $s = Net::SFTP::Foreign->new($host, user => $user, password => $password, backend => 'Net_SSH2', autodie => 1, queue_size => 1, block_size => 256);

$Net::SFTP::Foreign::debug = 131072;

#open STDERR, '>', 'trace.txt';

$s->{_backend}{_ssh2}->debug(-1);
$s->{_backend}{_ssh2}->trace(-1);

eval {
    my $n = 0;
    while (1) {
        for (@ARGV) {
            print STDERR "$n ($s->{_written_total}, $s->{_read_total}), copying $_\n";
            $s->rput($_, "/tmp/test/" . basename($_),
                wanted => sub { print STDERR "$n ($s->{_written_total}, $s->{_read_total}), copying $_[1]{filename}\n"; 1 } );
        }
        $n++;
    }
};
warn "error: $@\nsftp error: " . $s->error ."\nssh2 error: " . $s->{_backend}{_ssh2}->error;

