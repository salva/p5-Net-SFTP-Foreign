use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub write {
    @_ == 3 or croak 'Usage: $sftp->write($fh, $data)';

    my ($sftp, $rfh) = @_;
    $sftp->flush($rfh, 'in') or return undef;
    utf8::downgrade($_[2], 1) or croak "wide characters found in data";
    my $datalen = length $_[2];
    my $bout = $rfh->_bout;
    $$bout .= $_[2];
    my $len = length $$bout;

    $sftp->flush($rfh, 'out')
	if ($len >= $sftp->{_write_delay} or ($len and $sftp->{_autoflush} ));

    return $datalen;
}

1;
