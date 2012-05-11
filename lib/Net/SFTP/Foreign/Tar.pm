package Net::SFTP::Foreign::Tar;

our $VERSION = '1.63_04';

package Net::SFTP::Foreign;

use strict;
use warnings;
use Carp qw(carp croak);

use Net::SFTP::Foreign;
use Net::SFTP::Foreign::Helpers qw($debug _debug _catch_tainted_args);



sub tar {
    @_ >= 3 or croak 'Usage: $sftp->tar($remote, $local_archive, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $remote, $archive, %opts) = @_;

    


}
