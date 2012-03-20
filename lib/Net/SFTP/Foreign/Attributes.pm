package Net::SFTP::Foreign::Attributes;

our $VERSION = '1.68_05';

use strict;
use warnings;
use Carp;

use Net::SFTP::Foreign::Constants qw( :att );
use Net::SFTP::Foreign::Buffer;

sub new {
    my $class = shift;
    return bless { flags => 0}, $class;
}

sub new_from_stat {
    if (@_ > 1) {
	my ($class, undef, undef, $mode, undef,
	    $uid, $gid, undef, $size, $atime, $mtime) = @_;
	my $self = $class->new;

	$self->set_perm($mode);
	$self->set_ugid($uid, $gid);
	$self->set_size($size);
	$self->set_amtime($atime, $mtime);
	return $self;
    }
    return undef;
}

sub flags { shift->{flags} }

sub size { shift->{size} }

sub set_size {
    my ($self, $size) = @_;
    if (defined $size) {
	$self->{flags} |= SSH2_FILEXFER_ATTR_SIZE;
	$self->{size} = $size;
    }
    else {
	$self->{flags} &= ~SSH2_FILEXFER_ATTR_SIZE;
	delete $self->{size}
    }
}

sub uid { shift->{uid} }

sub gid { shift->{gid} }

sub set_ugid {
    my ($self, $uid, $gid) = @_;
    if (defined $uid and defined $gid) {
	$self->{flags} |= SSH2_FILEXFER_ATTR_UIDGID;
	$self->{uid} = $uid;
	$self->{gid} = $gid;
    }
    elsif (!defined $uid and !defined $gid) {
	$self->{flags} &= ~SSH2_FILEXFER_ATTR_UIDGID;
	delete $self->{uid};
	delete $self->{gid};
    }
    else {
	croak "wrong arguments for set_ugid"
    }
}

sub perm { shift->{perm} }

sub set_perm {
    my ($self, $perm) = @_;
    if (defined $perm) {
	$self->{flags} |= SSH2_FILEXFER_ATTR_PERMISSIONS;
	$self->{perm} = $perm;
    }
    else {
	$self->{flags} &= ~SSH2_FILEXFER_ATTR_PERMISSIONS;
	delete $self->{perm}
    }
}

sub atime { shift->{atime} }

sub mtime { shift->{mtime} }

sub set_amtime {
    my ($self, $atime, $mtime) = @_;
    if (defined $atime and defined $mtime) {
	$self->{flags} |= SSH2_FILEXFER_ATTR_ACMODTIME;
	$self->{atime} = $atime;
	$self->{mtime} = $mtime;
    }
    elsif (!defined $atime and !defined $mtime) {
	$self->{flags} &= ~SSH2_FILEXFER_ATTR_ACMODTIME;
	delete $self->{atime};
	delete $self->{mtime};
    }
    else {
	croak "wrong arguments for set_amtime"
    }
}

sub extended { @{shift->{extended} || [] } }

sub set_extended {
    my $self = shift;
    @_ & 1 and croak "odd number of arguments passed to set_extended";
    if (@_) {
        $self->{flags} |= SSH2_FILEXFER_ATTR_EXTENDED;
        $self->{extended} = [@_];
    }
    else {
        $self->{flags} &= ~SSH2_FILEXFER_ATTR_EXTENDED;
        delete $self->{extended};
    }
}

sub append_extended {
    my $self = shift;
    @_ & 1 and croak "odd number of arguments passed to append_extended";
    my $pairs = $self->{extended};
    if (@$pairs) {
        push @$pairs, @_;
    }
    else {
        $self->set_extended(@_);
    }
}

1;
__END__

=head1 NAME

Net::SFTP::Foreign::Attributes - File/directory attribute container

=head1 SYNOPSIS

    use Net::SFTP::Foreign;

    my $a1 = Net::SFTP::Foreign::Attributes->new();
    $a1->set_size($size);
    $a1->set_ugid($uid, $gid);

    my $a2 = $sftp->stat($file)
        or die "remote stat command failed: ".$sftp->status;

    my $size = $a2->size;
    my $mtime = $a2->mtime;

=head1 DESCRIPTION

I<Net::SFTP::Foreign::Attributes> encapsulates file/directory
attributes for I<Net::SFTP::Foreign>. It also provides serialization
and deserialization methods to encode/decode attributes into
I<Net::SFTP::Foreign::Buffer> objects.

=head1 USAGE

=over 4

=item Net::SFTP::Foreign::Attributes-E<gt>new()

Returns a new C<Net::SFTP::Foreign::Attributes> object.

=item $attrs-E<gt>flags

returns the value of the flags field.

=item $attrs-E<gt>size

returns the values of the size field or undef if it is not set.

=item $attrs-E<gt>uid

returns the value of the uid field or undef if it is not set.

=item $attrs-E<gt>gid

returns the value of the gid field or undef if it is not set.

=item $attrs-E<gt>perm

returns the value of the permissions field or undef if it is not set.

See also L<perlfunc/stat> for instructions on how to process the
returned value with the L<Fcntl> module.

For instance, the following code checks if some attributes object
corresponds to a directory:

  use Fctnl qw(S_ISDIR);
  ...
  if (S_ISDIR($attr->perm)) {
    # it is a directory!
  }

=item $attrs-E<gt>atime

returns the value of the atime field or undef if it is not set.

=item $attrs-E<gt>mtime

returns the value of the mtime field or undef if it is not set.

=item %extended = $attr-E<gt>extended

returns the vendor-dependent extended attributes

=item $attrs-E<gt>set_size($size)

sets the value of the size field, or if $size is undef removes the
field. The flags field is adjusted accordingly.

=item $attrs-E<gt>set_perm($perm)

sets the value of the permsissions field or removes it if the value is
undefined. The flags field is also adjusted.

=item $attr-E<gt>set_ugid($uid, $gid)

sets the values of the uid and gid fields, or removes them if they are
undefined values. The flags field is adjusted.

This pair of fields can not be set separatelly because they share the
same bit on the flags field and so both have to be set or not.

=item $attr-E<gt>set_amtime($atime, $mtime)

sets the values of the atime and mtime fields or remove them if they
are undefined values. The flags field is also adjusted.

=item $attr-E<gt>set_extended(%extended)

sets the vendor-dependent extended attributes

=item $attr-E<gt>append_extended(%more_extended)

adds more pairs to the list of vendor-dependent extended attributes

=back

=head1 COPYRIGHT

Copyright (c) 2006-2008 Salvador FandiE<ntilde>o.

All rights reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

=cut
