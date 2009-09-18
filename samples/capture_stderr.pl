#!/usr/bin/perl

use strict;
use warnings;

use Net::SFTP::Foreign;
use File::Temp;
use IPC::Open3;
use IPC::Open2;
use Fcntl qw(:mode O_NONBLOCK F_SETFL F_GETFL);

my $hostname = 'localhost';

my $ssherr = File::Temp->new
    or die "tempfile failed";

open my $stderr_save, '>&STDERR' or die "unable to dup STDERR";
open STDERR, '>&'.fileno($ssherr);

my $sftp = Net::SFTP::Foreign->new($hostname, more => qw(-v));

open STDERR, '>&'.fileno($stderr_save);

if ($sftp->error) {
  print "sftp error: ".$sftp->error."\n";
  seek($ssherr, 0, 0);
  while (<$ssherr>) {
    print "error: $_";
  }
}

close $ssherr;

