#!/usr/bin/perl

$Net::SFTP::Foreign::debug = 32768;

use strict;
use warnings;

my $file = shift // die "file name missing";

use Cwd;
use Net::SFTP::Foreign;

my $dir = getcwd;
my $ftp = Net::SFTP::Foreign->new('localhost', autodie => 1);
$ftp->setcwd($dir);
$ftp->get($file, "${file}_copy");
$ftp->disconnect();
