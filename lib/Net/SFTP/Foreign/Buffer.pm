package Net::SFTP::Foreign::Buffer;

our $VERSION = '1.72_01';

use strict;
use warnings;
use Carp;
use Encode;

require Exporter;
our @ISA = qw(Exporter);

our @EXPORT = qw( _buf_shift_uint32
                  _buf_shift_uint64
		  _buf_shift_uint8
		  _buf_shift_str
		  _buf_shift_utf8

                  _buf_skip_bytes
                  _buf_skip_str

		  _buf_push_uint32
                  _buf_push_uint64
		  _buf_push_uint8
		  _buf_push_str
		  _buf_push_utf8
 );



use constant HAS_QUADS => do {
    local $@;
    local $SIG{__DIE__};
    no warnings;
    eval q{ pack(Q => 0x1122334455667788) eq "\x11\x22\x33\x44\x55\x66\x77\x88" }
};


sub _buf_shift_uint8 { unpack C => substr($_[0], 0, 1, '') }

sub _buf_shift_uint32 { unpack N => substr($_[0], 0, 4, '') }

sub _buf_shift_uint64_quads { unpack Q => substr(${$_[0]}, 0, 8, '') }

sub _buf_shift_uint64_no_quads {
    length $_[0] >= 8 or return;
    my ($big, $small) = unpack(NN => substr($_[0], 0, 8, ''));
    if ($big) {
	# too big for an integer, try to handle it as a float:
	my $high = $big * 4294967296;
	my $result = $high + $small;
	unless ($result - $high == $small) {
	    # too big, even for a float, use a BigInt;
	    require Math::BigInt;
	    $result = Math::BigInt->new($big);
	    $result <<= 32;
	    $result += $small;
	}
	return $result;
    }
    return $small;
}

BEGIN {
    *_buf_shift_uint64 = (HAS_QUADS
			 ? \&_buf_shift_uint64_quads
			 : \&_buf_shift_uint64_no_quads);
}

sub _buf_shift_str {
    if (my ($len) = unpack N => substr($_[0], 0, 4, '')) {
	return substr($_[0], 0, $len, '')
	    if (length $_[0] >= $len);
    }
    ()
}

sub _buf_shift_utf8 {
    if (my ($len) = unpack N => substr($_[0], 0, 4, '')) {
	return Encode::decode(utf8 => substr($_[0], 0, $len, ''))
	    if (length $_[0] >= $len);
    }
    ()
}

sub _buf_skip_bytes { substr $_[0], 0, $_[1], '' }

sub _buf_skip_str {
    my $len = unpack(N => substr($_[0], 0, 4, ''));
    substr($_[0], 0, $len, '') if $len;
}


sub _buf_push_uint8 { $_[0] .= pack(C => int $_[1]) }

sub _buf_push_uint32 {
    Carp::confess("undefined uint32") unless defined $_[1];
    $_[0] .= pack(N => int $_[1]) }

sub _buf_push_uint64_quads { $_[0] .= pack(Q => int $_[1]) }

sub _buf_push_uint64_no_quads {
    my $high = int ( $_[1] / 4294967296);
    $_[0] .= pack(NN => $high, int($_[1] - $high * 4294967296));
}

BEGIN {
    *_buf_push_uint64 = (HAS_QUADS
			? \&_buf_push_uint64_quads
			: \&_buf_push_uint64_no_quads);
}

sub _buf_push_str  {
    utf8::downgrade($_[1]) or croak "UTF8 data reached the SFTP buffer";
    $_[0] .= pack(N => length $_[1]);
    $_[0] .= $_[1];
}

sub _buf_push_utf8 {
    my $octets = Encode::encode(utf8 => $_[1]);
    $_[0] .= pack(N => length $octets);
    $_[0] .= $octets;
}

1;
