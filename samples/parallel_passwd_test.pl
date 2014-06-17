#!/usr/bin/perl

use strict;
use warnings;
use 5.010;
use Net::SFTP::Foreign;

# See the following PerlMonks thread:
#
# "Net::SFTP::Foreign works intermittently"
#     http://perlmonks.org/?node_id=1090118

my $n = shift @ARGV // 10;
my $target = shift @ARGV // 'localhost';
my $password = shift @ARGV // 'foo';

my @pid;
$| = 1;

$Net::SFTP::Foreign::debug = ~0;
#$IO::Tty::DEBUG = 1;

use POSIX;

for my $i (1..$n) {
    my $pid = fork;
    unless ($pid) {
        unless (defined $pid) {
            warn "fork $i failed: $!";
            next;
        }

        my $strace;
        my $c = 0;
        OUT: while (1) {
            open STDERR, ">", "out.$i.$c";
            $c++;
            while (1) {
                warn "creating connection for worker $i";
                print STDOUT ".";
                my $sftp = Net::SFTP::Foreign->new($target, password => $password, more => '-vv');
                if ($sftp->error) {
                    warn "new failed: " . $sftp->error;
                    print STDOUT "worker $i failed\n";
                    # system "strace -f -o /tmp/strace.$i.out -p $$ &" unless $strace++;
                    next OUT;
                }
            }
        }
    }

    warn "process $pid forked for worker $i";

    push @pid, $pid;
}

1 while wait();

END { kill TERM => @pid; }
