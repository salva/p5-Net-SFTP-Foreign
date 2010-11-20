#!/usr/bin/perl

use strict;
use warnings;

use 5.010;

use Net::SFTP::Foreign;

# $Net::SFTP::Foreign::debug = 32;

$SIG{INT} = sub { say "interrupted" };
$| = 1;

my ($host, $file) = @ARGV;

my $sftp = Net::SFTP::Foreign->new($host);
$sftp->error and die "Unable to connecto to $host";

while (!$sftp->error) {
    say "transferring $file";
    $sftp->get($file, "/tmp/deleteme");
    system "ls -l /tmp/deleteme";
}

