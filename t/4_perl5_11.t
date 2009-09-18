#!/usr/bin/perl

use strict;
use warnings;

use Test::More;

use lib "./t";
use common;

my $server; # = 'localhost';
my $sscmd = sftp_server;

plan skip_all => "tests not supported on inferior OS"
    if (is_windows and eval "no warnings; getlogin ne 'salva'");
plan skip_all => "sftp-server not found"
    unless defined $sscmd;

plan tests => 2;

use Net::SFTP::Foreign;

my $sftp = Net::SFTP::Foreign->new(open2_cmd => $sscmd, timeout => 20);
my $fn = File::Spec->rel2abs('t/data.txd');

ok(my $fh = $sftp->open($fn), "open");
ok (!eof($fh), "eof");
