package Net::SFTP::Foreign;

our $VERSION = '2.00_01';

use strict;
use warnings;
use warnings::register;

use 5.008;

use Carp qw(carp croak);

use Symbol ();
use Errno ();
use Fcntl;
require Encode;

# we make $Net::SFTP::Foreign::Helpers::debug an alias for
# $Net::SFTP::Foreign::debug so that the user can set it without
# knowing anything about the Helpers package!
our $debug;
BEGIN { *Net::SFTP::Foreign::Helpers::debug = \$debug };
use Net::SFTP::Foreign::Helpers qw(_is_reg _is_lnk _is_dir _debug
                                   _sort_entries _gen_wanted
                                   _gen_converter _hexdump
                                   _ensure_list _catch_tainted_args
                                   _file_part _umask_save_and_set
                                   _untaint);
use Net::SFTP::Foreign::Constants qw( :fxp :flags :att
				      :status :error
				      SSH2_FILEXFER_VERSION );
use Net::SFTP::Foreign::Attributes;
use Net::SFTP::Foreign::Buffer;
require Net::SFTP::Foreign::Common;
our @ISA = qw(Net::SFTP::Foreign::Common);

use Method::LazyLoad qw(atomic_rename closedir _fill_read_cache
                        get_content getc get get_symlink hardlink ls
                        lstat mget mkdir mkpath mput put_content put
                        put_symlink readdir _readline readline read
                        rename rget rput rremove seek setcwd setstat
                        sftpread sftpwrite stat statvfs symlink
                        write);

our $windows;
our $dirty_cleanup;

BEGIN {
    $windows = $^O =~ /in(?:32|64)/i;
    $dirty_cleanup = ($^O =~ /solaris/i ? 2 : 1)
        unless defined $dirty_cleanup;
}

sub _queue_msg {
    my $sftp = shift;
    my $code = shift;
    my $id = $sftp->{_msg_id}++;
    return ($sftp->_queue_msg_low($code, uint32 => $id, @_) ? $id : undef)
}

my %buffer_packer_sub =   ( uint8      => \&_buf_push_uint8,
                            uint32     => \&_buf_push_uint32,
                            uint64     => \&_buf_push_uint64,
                            str        => \&_buf_push_str,
                            utf8       => \&_buf_push_uint8 );

my %buffer_packer_method = ( abs_path  => '_buf_push_abs_path',
                             path      => '_buf_push_path',
                             fh        => '_buf_push_fh',
                             attrs     => '_buf_push_attrs');

sub _queue_msg_low {
    my $sftp = shift;
    my $code = shift;
    for ($sftp->{_bout}) {
        my $offset = length $_;
        $_ .= pack(NC => 0, $code);
        for (my $i = 0; $i < @_; $i += 2) {
            my $packer = $buffer_packer_sub{$_[$i]};
            if ($packer) {
                $packer->($_, $_[$i+1])
            }
            else {
                $packer = $buffer_packer_method{$_[$i]};
                if ($packer) {
                    unless ($sftp->$packer($_, $_[$i+1])) {
                        $debug and $debug & 1 and _debug "packing aborting because packer $_[$i] failed, ix: $i";
                        goto ERROR;
                    }
                }
                else {
                    Carp::confess("internal error: unknown packer type $_[$i]");
                }
            }
        }
        my $len = length($_) - $offset - 4;

        if ($len > 33999) {
            $debug and $debug & 1 and _debug "long packet generated, len: $len";
            $sftp->_set_status(SSH2_FX_BAD_MESSAGE);
            $sftp->_set_error(SFTP_ERR_LOCAL_BAD_MESSAGE, "The generated packed was too big");
            goto ERROR;
        }

        substr($_, $offset, 4, pack(N => $len));

        if ($debug and $debug & 1) {
            $sftp->{_queued}++;
            _debug(sprintf("queueing msg len: %i, code:%i, id:%i ... [%d]",
                           unpack(NCN => substr($_, $offset)), ++$sftp->{_queued}));
            $debug & 16 and _hexdump(substr($_, $offset));
        }
        return 1;

    ERROR:
        # discard incomplete packet:
        substr($_, $offset, length $_ - $offset, '');
        return undef;
    }
}

sub _buf_push_attrs {
    my ($sftp, undef, $a) = @_;
    if (defined $a) {
        my $flags = $a->flags;
        _buf_push_uint32($_[1], $flags);
        if ($flags & SSH2_FILEXFER_ATTR_SIZE) {
            _buf_push_uint64($_[1], $a->size);
        }
        if ($flags & SSH2_FILEXFER_ATTR_UIDGID) {
            _buf_push_uint32($_[1], $a->uid);
            _buf_push_uint32($_[1], $a->gid);
        }
        if ($flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
            _buf_push_uint32($_[1], $a->perm);
        }
        if ($flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
            _buf_push_uint32($_[1], $a->atime);
            _buf_push_uint32($_[1], $a->mtime);
        }
        if ($flags & SSH2_FILEXFER_ATTR_EXTENDED) {
            my $pairs = $a->extended;
            _buf_push_uint32($_[1], int(@$pairs / 2));
            for my $str (@$pairs) {
                _buf_push_str($_[1], $str);
            }
        }
    }
    else {
        _buf_push_uint32($_[1], 0);
    }
    1;
}

sub _buf_push_path {
    _buf_push_str($_[1], Encode::encode($_[0]->{_fs_encoding}, $_[2]));
    1;
}

sub _buf_push_abs_path {
    _buf_push_str($_[1], Encode::encode($_[0]->{_fs_encoding},
                                        $_[0]->_rel2abs($_[2])));
    1;
}

sub _buf_push_fh {
    if (defined (my $rid = $_[0]->_rid($_[2]))) {
        _buf_push_str($_[1], $rid);
        return 1;
    }
    undef;
}

sub _do_io { $_[0]->{_backend}->_do_io(@_) }

sub _conn_lost {
    my ($sftp, $status, $err, @str) = @_;
    $debug and $debug & 32 and _debug("_conn_lost");
    undef $sftp->{_connected};
    unless ($sftp->{_error}) {
	$sftp->_set_status(defined $status ? $status : SSH2_FX_CONNECTION_LOST);
	$sftp->_set_error((defined $err ? $err : SFTP_ERR_CONNECTION_BROKEN),
			  (@str ? @str : "Connection to remote server is broken"));
    }
}

sub _conn_failed {
    my $sftp = shift;
    $sftp->_conn_lost(SSH2_FX_NO_CONNECTION,
                      SFTP_ERR_CONNECTION_BROKEN,
                      @_)
	unless $sftp->{_error};
}

sub _get_msg {
    my $sftp = shift;

    $debug and $debug & 1 and _debug("waiting for message... [$sftp->{_queued}]");
    unless ($sftp->_do_io($sftp->{_timeout})) {
	$sftp->_conn_lost(undef, undef, "Connection to remote server stalled");
	return undef;
    }
    my $msg = _buf_shift_str($sftp->{_bin});

    if ($debug and $debug & 1) {
	$sftp->{_queued}--;
        my ($code, $id, $status) = unpack( CNN => $msg);
	$id = '-' if $code == SSH2_FXP_VERSION;
        $status = '-' unless $code == SSH2_FXP_STATUS;
	_debug(sprintf("got it!, len:%i, code:%i, id:%s, status: %s",
                       length($msg), $code, $id, $status));
        $debug & 8 and _hexdump($msg);
    }

    return $msg;
}

sub _croak_bad_options {
    @_ and croak "Invalid option(s) '" . CORE::join("', '", @_) . "' or bad combination";
}

sub new {
    ${^TAINT} and &_catch_tainted_args;

    my $class = shift;
    unshift @_, 'host' if @_ & 1;
    my %opts = @_;

    my $sftp = { _msg_id => 0,
		 _bout => '',
		 _bin => '',
		 _connected => 1,
		 _queued => 0 };
    bless $sftp, $class;

    if ($debug) {
        _debug "This is Net::SFTP::Foreign $Net::SFTP::Foreign::VERSION";
        _debug "Loaded from $INC{'Net/SFTP/Foreign.pm'}";
        _debug "Running on Perl $^V for $^O";
        _debug "debug set to $debug";
        _debug "windows set to " . (defined $windows ? $windows : '<undef>');
        _debug "dirty_cleanup set to " . (defined $dirty_cleanup ? $dirty_cleanup : '<undef>');
        _debug "~0 is " . ~0;
    }

    $sftp->_clear_error_and_status;

    my $backend = delete $opts{backend};
    unless (ref $backend) {
	$backend = ($windows ? 'Windows' : 'Unix')
	    unless (defined $backend);
	$backend =~ /^\w+$/
	    or croak "Bad backend name $backend";
	my $backend_class = "Net::SFTP::Foreign::Backend::$backend";
	eval "require $backend_class; 1"
	    or croak "Unable to load backend $backend: $@";
	$backend = $backend_class->_new($sftp, \%opts);
    }
    $sftp->{_backend} = $backend;

    if ($debug) {
        my $class = ref($backend) || $backend;
        no strict 'refs';
        my $version = ${$class .'::VERSION'} || 0;
        _debug "Using backend $class $version";
    }

    my %defs = $backend->_defaults;

    $sftp->{_autodie} = delete $opts{autodie};
    $sftp->{_block_size} = delete $opts{block_size} || $defs{block_size} || 32*1024;
    $sftp->{_queue_size} = delete $opts{queue_size} || $defs{queue_size} || 32;
    $sftp->{_read_ahead} = $defs{read_ahead} || $sftp->{_block_size} * 4;
    $sftp->{_write_delay} = $defs{write_delay} || $sftp->{_block_size} * 8;
    $sftp->{_autoflush} = delete $opts{autoflush};
    $sftp->{_late_set_perm} = delete $opts{late_set_perm};
    $sftp->{_dirty_cleanup} = delete $opts{dirty_cleanup};

    $sftp->{_timeout} = delete $opts{timeout};
    defined $sftp->{_timeout} and $sftp->{_timeout} <= 0 and croak "invalid timeout";

    $sftp->{_fs_encoding} = delete $opts{fs_encoding};
    if (defined $sftp->{_fs_encoding}) {
        $] < 5.008
            and carp "fs_encoding feature is not supported in this perl version $]";
    }
    else {
        $sftp->{_fs_encoding} = 'utf8';
    }

    $sftp->autodisconnect(delete $opts{autodisconnect});

    $backend->_init_transport($sftp, \%opts);
    %opts and _croak_bad_options(keys %opts);

    $sftp->_init unless $sftp->{_error};
    $backend->_after_init($sftp);
    $sftp
}

sub autodisconnect {
    my ($sftp, $ad) = @_;
    if (defined $ad) {
        $sftp->{_disconnect_by_pid} = ( $ad == 0 ?    -1 :
                                        $ad == 1 ? undef :
                                        $ad == 2 ?    $$ :
                                        croak "bad value '$ad' for autodisconnect");
    }
    1;
}

sub disconnect {
    my $sftp = shift;
    my $pid = $sftp->{pid};

    $debug and $debug & 4 and _debug("$sftp->disconnect called (ssh pid: ".($pid||'<undef>').")");

    local $sftp->{_autodie};
    $sftp->_conn_lost;

    if (defined $pid) {
        close $sftp->{ssh_out} if (defined $sftp->{ssh_out} and not $sftp->{_ssh_out_is_not_dupped});
        close $sftp->{ssh_in} if defined $sftp->{ssh_in};

        local ($?, $@, $SIG{__DIE__}, $SIG{__WARN__}, $SIG{ALRM});
        if ($windows) {
	    kill KILL => $pid
                and waitpid($pid, 0);
        }
        else {
	    my $dirty = ( defined $sftp->{_dirty_cleanup}
			  ? $sftp->{_dirty_cleanup}
			  : $dirty_cleanup );

	    if ($dirty) {
                kill TERM => $pid if $dirty > 1;
		for my $sig (qw(TERM TERM KILL KILL)) {
                    my $r;
                    eval {
                        alarm 8;
                        $r = waitpid($pid, 0);
                        alarm 0;
                    };
                    last if defined $r and ( $r > 0 or $! == Errno::ECHILD());
                    kill $sig => $pid;
		}
	    }
	    else {
		while (1) {
		    last if waitpid($pid, 0) > 0;
                    last if $! == Errno::ECHILD();
		    $! == Errno::EINTR() or
                        warn "internal error: unexpected error in waitpid($pid): $!";
		}
	    }
        }
    }
    1
}

sub DESTROY {
    my $sftp = shift;
    local ($?, $!, $@);
    my $dbpid = $sftp->{_disconnect_by_pid};
    $debug and $debug & 4 and _debug("$sftp->DESTROY called (current pid: $$, disconnect_by_pid: ".($dbpid||'').")");
    $sftp->disconnect if (!defined $dbpid or $dbpid == $$);
}

sub _init {
    my $sftp = shift;
    $sftp->_queue_msg_low(SSH2_FXP_INIT, uint32 => SSH2_FILEXFER_VERSION);
    my $msg = $sftp->_get_msg;
    unless (defined $msg) {
        if ($sftp->{_status} == SSH2_FX_CONNECTION_LOST
         and $sftp->{_password_authentication}
         and $sftp->{_password_sent}) {
            $sftp->_set_error(SFTP_ERR_PASSWORD_AUTHENTICATION_FAILED,
			  "Password authentication failed or connection lost");
        }
        return undef;
    }

    my $type = _buf_shift_uint8($msg);
    if ($type != SSH2_FXP_VERSION) {
        $sftp->_conn_lost(SSH2_FX_BAD_MESSAGE,
                          SFTP_ERR_REMOTE_BAD_MESSAGE,
                          "bad packet type, expecting SSH2_FXP_VERSION, got $type");
        return undef;

    }

    my $version = $sftp->{server_version} = _buf_shift_uint32($msg);
    $sftp->{server_extensions} = {};
    while (length $msg) {
        my $key   = _buf_shift_str($msg);
        my $value = _buf_shift_str($msg);
        $sftp->{server_extensions}{$key} = $value;
        if ($key eq 'vendor-id') {
            $sftp->{server_extensions__vendor_id} = [ _buf_shift_utf8($value),
                                                      _buf_shift_utf8($value),
                                                      _buf_shift_utf8($value),
                                                      _buf_shift_uint64($value) ];
        }
    }
    return $version;
}

sub server_extensions { %{shift->{server_extensions}} }

sub _check_extension {
    my ($sftp, $name, $version, $error, $errstr) = @_;
    my $ext = $sftp->{server_extensions}{$name};
    return 1 if (defined $ext and $ext == $version);

    $sftp->_set_status(SSH2_FX_OP_UNSUPPORTED);
    $sftp->_set_error($error, "$errstr: extended operation not supported by server");
    return undef;
}

sub _get_msg_and_check {
    my ($sftp, $etype, $eid, $err, $errstr) = @_;
    defined $eid or return undef;

    my $msg = $sftp->_get_msg;
    defined $msg or return undef;

    $sftp->_clear_error_and_status;

    my $type = _buf_shift_uint8($msg);
    my $id = _buf_shift_uint32($msg);

    unless ($id == $eid) {
        $sftp->_conn_lost(SSH2_FX_BAD_MESSAGE,
                          SFTP_ERR_REMOTE_BAD_MESSAGE,
                          $errstr, "bad packet sequence, expected $eid, got $id");
        return undef;
    }

    if ($type == SSH2_FXP_STATUS) {
        my $code = _buf_shift_uint32($msg);
        my $str = _buf_shift_utf8($msg);
        my $status = $sftp->_set_status($code, (defined $str ? $str : ()));

        $sftp->_set_error($err, $errstr, $status)
            unless $etype == SSH2_FXP_STATUS and $status == SSH2_FX_OK;

        return undef;
    }

    if ($type != $etype) {
        $sftp->_conn_lost(SSH2_FX_BAD_MESSAGE,
                          SFTP_ERR_REMOTE_BAD_MESSAGE,
                          $errstr, "bad packet type, expected $etype packet, got $type");
        return undef;
    }

    return $msg;
}

# reads SSH2_FXP_HANDLE packet and returns handle, or undef on failure
sub _get_handle {
    my ($sftp, $eid, $error, $errstr) = @_;
    if (defined(my $msg = $sftp->_get_msg_and_check(SSH2_FXP_HANDLE, $eid,
                                                    $error, $errstr))) {
	return _buf_shift_str($msg);
    }
    return undef;
}

sub _rid {
    my ($sftp, $rfh) = @_;
    my $rid = $rfh->_rid;
    unless (defined $rid) {
	$sftp->_set_error(SFTP_ERR_REMOTE_ACCESING_CLOSED_FILE,
			  "Couldn't access a file that has been previosly closed");
    }
    $rid
}

sub _get_status_msg_and_check {
    my $sftp = shift;
    $sftp->_get_msg_and_check(SSH2_FXP_STATUS, @_);
    return !$sftp->{_error};
}

sub cwd {
    @_ == 1 or croak 'Usage: $sftp->cwd()';

    my $sftp = shift;
    return defined $sftp->{cwd} ? $sftp->{cwd} : $sftp->realpath('');
}

## SSH2_FXP_OPEN (3)
# returns handle on success, undef on failure
sub open {
    (@_ >= 2 and @_ <= 4)
	or croak 'Usage: $sftp->open($path [, $flags [, $attrs]])';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $path, $flags, $a) = @_;
    defined $flags or $flags = SSH2_FXF_READ;
    my $id = $sftp->_queue_msg(SSH2_FXP_OPEN,
                               abs_path => $path, uint32 => $flags, attrs => $a);

    my $rid = $sftp->_get_handle($id,
                                 SFTP_ERR_REMOTE_OPEN_FAILED,
                                 "Couldn't open remote file '$path'");

    if ($debug and $debug & 2) {
        if (defined $rid) {
            _debug("new remote file '$path' open, rid:");
            _hexdump($rid);
        }
        else {
            _debug("open failed: $sftp->{_status}");
        }
    }

    defined $rid or return undef;

    my $fh = Net::SFTP::Foreign::FileHandle->_new_from_rid($sftp, $rid);
    $fh->_flag(append => 1) if ($flags & SSH2_FXF_APPEND);

    $fh;
}

## SSH2_FXP_OPENDIR (11)
sub opendir {
    @_ == 2 or croak 'Usage: $sftp->opendir($path)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $path) = @_;
    my $id = $sftp->_queue_msg(SSH2_FXP_OPENDIR, abs_path => $path);
    my $rid = $sftp->_get_handle($id, SFTP_ERR_REMOTE_OPENDIR_FAILED,
				 "Couldn't open remote dir '$path'");

    if ($debug and $debug & 2) {
        _debug("new remote dir '$path' open, rid:");
        _hexdump($rid);
    }

    defined $rid
	or return undef;

    Net::SFTP::Foreign::DirHandle->_new_from_rid($sftp, $rid, 0)
}

sub tell {
    @_ == 2 or croak 'Usage: $sftp->tell($fh)';

    my ($sftp, $rfh) = @_;
    return $rfh->_pos + length ${$rfh->_bout};
}

sub eof {
    @_ == 2 or croak 'Usage: $sftp->eof($fh)';

    my ($sftp, $rfh) = @_;
    $sftp->_fill_read_cache($rfh, 1);
    return length(${$rfh->_bin}) == 0
}

sub _write {
    my ($sftp, $rfh, $off, $cb) = @_;

    $sftp->_clear_error_and_status;

    my $rid = $sftp->_rid($rfh);
    defined $rid or return undef;

    my $qsize = $sftp->{_queue_size};

    my @msgid;
    my @written;
    my $written = 0;
    my $end;

    while (!$end or @msgid) {
	while (!$end and @msgid < $qsize) {
	    my $data = $cb->();
	    if (defined $data and length $data) {
		my $id = $sftp->_queue_msg(SSH2_FXP_WRITE, str => $rid,
                                           uint64 => $off + $written, str => $data);
		push @written, $written;
		$written += length $data;
		push @msgid, $id;
	    }
	    else {
		$end = 1;
	    }
	}

	my $eid = shift @msgid;
	my $last = shift @written;
	unless ($sftp->_get_status_msg_and_check($eid,
                                                 SFTP_ERR_REMOTE_WRITE_FAILED,
                                                 "Couldn't write to remote file")) {

	    # discard responses to queued requests:
	    $sftp->_get_msg for @msgid;
	    return $last;
	}
    }

    return $written;
}

sub flush {
    (@_ >= 2 and @_ <= 3)
	or croak 'Usage: $sftp->flush($fh [, $direction])';

    my ($sftp, $rfh, $dir) = @_;

    $sftp->_clear_error_and_status;

    $dir ||= '';

    if ($dir ne 'out') { # flush in!
	${$rfh->_bin} = '';
    }

    if ($dir ne 'in') { # flush out!
	my $bout = $rfh->_bout;
	my $len = length $$bout;
	if ($len) {
	    my $start;
	    my $append = $rfh->_flag('append');
	    if ($append) {
		my $attr = $sftp->stat($rfh) or return undef;
		$start = $attr->size;
	    }
	    else {
		$start = $rfh->_pos;
		${$rfh->_bin} = '';
	    }
	    my $off = 0;
	    my $written = $sftp->_write($rfh, $start,
					sub {
					    my $data = substr($$bout, $off, $sftp->{_block_size});
					    $off += length $data;
					    $data;
					} );
	    $rfh->_inc_pos($written)
		unless $append;

	    substr($$bout, 0, $written, '');
	    $written == $len or return undef;
	}
    }
    1;
}

sub _buf_shift_attrs {
    my $sftp = shift;
    my $a = Net::SFTP::Foreign::Attributes->new;
    my $flags = _buf_shift_uint32($_[0]);
    if ($flags & SSH2_FILEXFER_ATTR_SIZE) {
        $a->set_size(_untaint(_buf_shift_uint64($_[0])));
    }
    if ($flags & SSH2_FILEXFER_ATTR_UIDGID) {
        $a->set_ugid(_untaint(_buf_shift_uint32($_[0])),
                     _untaint(_buf_shift_uint32($_[0])));
    }
    if ($flags & SSH2_FILEXFER_ATTR_PERMISSIONS) {
        $a->set_perm(_untaint(_buf_shift_uint32($_[0])));
    }
    if ($flags & SSH2_FILEXFER_ATTR_ACMODTIME) {
        $a->set_amtime(_untaint(_buf_shift_uint32($_[0])),
                       _untaint(_buf_shift_uint32($_[0])));
    }
    if ($flags & SSH2_FILEXFER_ATTR_EXTENDED) {
        my $n = _buf_shift_uint32($_[0]);
        my @ext;
        for (0 .. $n - 1) {
            my $key = _buf_get_str($_[0]);
            my $value = _buf_get_str($_[0]);
            unless (defined $key and defined $value) {
                $sftp->_conn_lost(SSH2_FX_BAD_MESSAGE, SFTP_ERR_REMOTE_BAD_MESSAGE,
                                  "attribute extensions missing from packet");
                return;
            }
            push @ext, $key, $value;
        }
        $a->{extended} = \@ext;
    }
    return $a;
}

sub _buf_skip_attrs {
    my $sftp = shift;
    my $flags = _buf_shift_uint32($_[0]);
    my $skip = 0;
    $skip += 8 if $flags & SSH2_FILEXFER_ATTR_SIZE;
    $skip += 8 if $flags & SSH2_FILEXFER_ATTR_UIDGID;
    $skip += 4 if $flags & SSH2_FILEXFER_ATTR_PERMISSIONS;
    $skip += 8 if $flags & SSH2_FILEXFER_ATTR_ACMODTIME;
    _buf_skip_bytes($_[0], $skip);
    if ($flags & SSH2_FILEXFER_ATTR_EXTENDED) {
        my $n = _buf_shift_uint32($_[0]);
        for (1 .. 2 * $n) {
            last unless length $_[0];
            _buf_shift_str($_[0]);
        }
    }
}

sub _buf_shift_path {
    my $sftp = shift;
    my $str = _buf_shift_str($_[0]);
    unless (defined $str) {
        $sftp->_conn_lost(SSH2_FX_BAD_MESSAGE, SFTP_ERR_REMOTE_BAD_MESSAGE,
                          "path string missing from packet");
        return;
    }
    Encode::decode($sftp->{_fs_encoding}, $str);
}

sub _is_fh { ref $_[0] and UNIVERSAL::isa($_[0], 'Net::SFTP::Foreign::FileHandle') }

sub _queue_pofh_msg {
    my $sftp = shift;
    my $code_path = shift;
    my $code_fh = shift;
    my $pofh = shift;
    $sftp->_queue_msg( ( (ref $pofh and UNIVERSAL::isa($pofh, 'Net::SFTP::Foreign::FileHandle'))
                         ? ($code_fh, fh => $pofh)
                         : ($code_path, abs_path => $pofh) ), @_);
}

sub _gen_remove_method {
    my($name, $code, $error, $errstr) = @_;
    my $sub = sub {
	@_ == 2 or croak "Usage: \$sftp->$name(\$path)";
        ${^TAINT} and &_catch_tainted_args;

        my ($sftp, $path) = @_;
        my $id = $sftp->_queue_msg($code, abs_path => $path);
        $sftp->_get_status_msg_and_check($id, $error, $errstr);
    };
    no strict 'refs';
    *$name = $sub;
}

_gen_remove_method(remove => SSH2_FXP_REMOVE,
                   SFTP_ERR_REMOTE_REMOVE_FAILED, "Couldn't delete remote file");
_gen_remove_method(rmdir => SSH2_FXP_RMDIR,
                   SFTP_ERR_REMOTE_RMDIR_FAILED, "Couldn't remove remote directory");

sub join {
    my $sftp = shift;
    my $a = '.';
    while (@_) {
	my $b = shift;
	if (defined $b) {
	    $b =~ s|^(?:\./+)+||;
	    if (length $b and $b ne '.') {
		if ($b !~ m|^/| and $a ne '.' ) {
		    $a = ($a =~ m|/$| ? "$a$b" : "$a/$b");
		}
		else {
		    $a = $b
		}
		$a =~ s|(?:/+\.)+/?$|/|;
		$a =~ s|(?<=[^/])/+$||;
		$a = '.' unless length $a;
	    }
	}
    }
    $a;
}

sub _rel2abs {
    my ($sftp, $path) = @_;
    my $old = $path;
    my $cwd = $sftp->{cwd};
    $path = $sftp->join($sftp->{cwd}, $path);
    $debug and $debug & 4096 and _debug("'$old' --> '$path'");
    return $path
}

sub _gen_setstat_shortcut {
    my ($name, $attrs_flag, @arg_types) = @_;
    my $nargs = 2 + @arg_types;
    my $usage = ("\$sftp->$name("
                 . CORE::join(', ', '$path_or_fh', map "arg$_", 1..@arg_types)
                 . ')');

    my $sub = sub {
        @_ == $nargs or croak $usage;
        ${^TAINT} and &_catch_tainted_args;

        my $sftp = shift;
        my $pofh = shift;
        my $id = $sftp->_queue_pofh_msg(SSH2_FXP_SETSTAT, SSH2_FXP_FSETSTAT, $pofh,
                                            int32 => $attrs_flag,
                                            map { $arg_types[$_] => $_[$_] } 0..$#arg_types);
        $sftp->_get_status_msg_and_check($id,
                                         SFTP_ERR_REMOTE_SETSTAT_FAILED,
                                         "Couldn't setstat remote file ($name)");
    };
    no strict 'refs';
    *$name = $sub;
}

_gen_setstat_shortcut(truncate => SSH2_FILEXFER_ATTR_SIZE,        'int64');
_gen_setstat_shortcut(chown    => SSH2_FILEXFER_ATTR_UIDGID,      'int32', 'int32');
_gen_setstat_shortcut(chmod    => SSH2_FILEXFER_ATTR_PERMISSIONS, 'int32');
_gen_setstat_shortcut(utime    => SSH2_FILEXFER_ATTR_ACMODTIME,   'int32', 'int32');

sub _close {
    @_ == 2 or croak 'Usage: $sftp->close($fh)';

    my ($sftp, $fh) = @_;
    if ($debug and $debug & 2) {
        _debug sprintf("closing file/dir handle, return: %s, rid:");
        _hexdump($sftp->_rid($fh));
    }
    my $id = $sftp->_queue_msg(SSH2_FXP_CLOSE, fh => $fh);
    $sftp->_get_status_msg_and_check($id,
                                     SFTP_ERR_REMOTE_CLOSE_FAILED,
                                     "Couldn't close remote file");
}

sub close {
    @_ == 2 or croak 'Usage: $sftp->close($fh)';
    ${^TAINT} and &_catch_tainted_args;
    my ($sftp, $rfh) = @_;

    $rfh->_check_is_file;
    $sftp->flush($rfh);
    $sftp->_with_save_error(_close => $rfh) and $rfh->_close;
    return !$sftp->{_error};
}

sub _gen_getpath_method {
    my ($name, $code, $error) = @_;
    my $sub = sub {
	@_ == 2 or croak "Usage: \$sftp->$name(\$path)";
        ${^TAINT} and &_catch_tainted_args;

	my ($sftp, $path) = @_;
	my $id = $sftp->_queue_msg($code, abs_path => $path);
	if (defined(my $msg = $sftp->_get_msg_and_check(SSH2_FXP_NAME, $id,
                                                        $error, "$name failed"))) {
            _buf_shift_uint32($msg) > 0
		and return $sftp->_buf_shift_path($msg);

	    $sftp->_set_error($error, "$name failed, no entries on reply");
	}
	return undef;
    };
    no strict 'refs';
    *$name = $sub;
}

_gen_getpath_method(realpath => SSH2_FXP_REALPATH, SFTP_ERR_REMOTE_REALPATH_FAILED);
_gen_getpath_method(readlink => SSH2_FXP_READLINK, SFTP_ERR_REMOTE_READLINK_FAILED);

sub _queue_extended_msg {
    my $sftp = shift;
    my $extension = shift;
    my $version = shift;
    my $error = shift;
    my $error_str = shift;
    $sftp->_check_extension($extension, $version, $error, $error_str) and
        $sftp->_queue_msg(SSH2_FXP_EXTENDED, str => $extension, @_);
}

sub _inc_numbered {
    $_[0] =~ s{^(.*)\((\d+)\)((?:\.[^\.]*)?)$}{"$1(" . ($2+1) . ")$3"}e or
    $_[0] =~ s{((?:\.[^\.]*)?)$}{(1)$1};
    $debug and $debug & 128 and _debug("numbering to: $_[0]");
}

sub abort {
    my $sftp = shift;
    $sftp->_set_error(SFTP_ERR_ABORTED, ($@ ? $_[0] : "Aborted"));
}

package Net::SFTP::Foreign::Handle;

use Tie::Handle;
our @ISA = qw(Tie::Handle);
our @CARP_NOT = qw(Net::SFTP::Foreign Tie::Handle);

my $gen_accessor = sub {
    my $ix = shift;
    sub {
	my $st = *{shift()}{ARRAY};
	if (@_) {
	    $st->[$ix] = shift;
	}
	else {
	    $st->[$ix]
	}
    }
};

my $gen_proxy_method = sub {
    my $method = shift;
    sub {
	my $self = $_[0];
	$self->_check
	    or return undef;

	my $sftp = $self->_sftp;
	if (wantarray) {
	    my @ret = $sftp->$method(@_);
	    $sftp->_set_errno unless @ret;
	    return @ret;
	}
	else {
	    my $ret = $sftp->$method(@_);
	    $sftp->_set_errno unless defined $ret;
	    return $ret;
	}
    }
};

my $gen_not_supported = sub {
    sub {
	$! = Errno::ENOTSUP();
	undef
    }
};

sub TIEHANDLE { return shift }

# sub UNTIE {}

sub _new_from_rid {
    my $class = shift;
    my $sftp = shift;
    my $rid = shift;
    my $flags = shift || 0;

    my $self = Symbol::gensym;
    bless $self, $class;
    *$self = [ $sftp, $rid, 0, $flags, @_];
    tie *$self, $self;

    $self;
}

sub _close {
    my $self = shift;
    @{*{$self}{ARRAY}} = ();
}

sub _check {
    return 1 if defined(*{shift()}{ARRAY}[0]);
    $! = Errno::EBADF;
    undef;
}

sub FILENO {
    my $self = shift;
    $self->_check
	or return undef;

    my $hrid = unpack 'H*' => $self->_rid;
    "-1:sftp(0x$hrid)"
}

sub _sftp { *{shift()}{ARRAY}[0] }
sub _rid { *{shift()}{ARRAY}[1] }

* _pos = $gen_accessor->(2);

sub _inc_pos {
    my ($self, $inc) = @_;
    *{shift()}{ARRAY}[2] += $inc;
}


my %flag_bit = (append => 0x1);

sub _flag {
    my $st = *{shift()}{ARRAY};
    my $fn = shift;
    my $flag = $flag_bit{$fn};
    Carp::croak("unknown flag $fn") unless defined $flag;
    if (@_) {
	if (shift) {
	    $st->[3] |= $flag;
	}
	else {
	    $st->[3] &= ~$flag;
	}
    }
    $st->[3] & $flag ? 1 : 0
}

sub _check_is_file {
    Carp::croak("expecting remote file handler, got directory handler");
}
sub _check_is_dir {
    Carp::croak("expecting remote directory handler, got file handler");
}

my $autoloaded;
sub AUTOLOAD {
    my $self = shift;
    our $AUTOLOAD;
    if ($autoloaded) {
	my $class = ref $self || $self;
	Carp::croak qq|Can't locate object method "$AUTOLOAD" via package "$class|;
    }
    else {
	$autoloaded = 1;
	require IO::File;
	require IO::Dir;
	my ($method) = $AUTOLOAD =~ /^.*::(.*)$/;
	$self->$method(@_);
    }
}

package Net::SFTP::Foreign::FileHandle;
our @ISA = qw(Net::SFTP::Foreign::Handle IO::File);

sub _new_from_rid {
    my $class = shift;
    my $sftp = shift;
    my $rid = shift;
    my $flags = shift;

    my $self = $class->SUPER::_new_from_rid($sftp, $rid, $flags, '', '');
}

sub _check_is_file {}

sub _bin { \(*{shift()}{ARRAY}[4]) }
sub _bout { \(*{shift()}{ARRAY}[5]) }

sub WRITE {
    my ($self, undef, $length, $offset) = @_;
    $self->_check
	or return undef;

    $offset = 0 unless defined $offset;
    $offset = length $_[1] + $offset if $offset < 0;
    $length = length $_[1] unless defined $length;

    my $sftp = $self->_sftp;

    my $ret = $sftp->write($self, substr($_[1], $offset, $length));
    $sftp->_set_errno unless defined $ret;
    $ret;
}

sub READ {
    my ($self, undef, $len, $offset) = @_;
    $self->_check
	or return undef;

    $_[1] = '' unless defined $_[1];
    $offset ||= 0;
    if ($offset > length $_[1]) {
	$_[1] .= "\0" x ($offset - length $_[1])
    }

    if ($len == 0) {
	substr($_[1], $offset) = '';
	return 0;
    }

    my $sftp = $self->_sftp;
    $sftp->_fill_read_cache($self, $len);

    my $bin = $self->_bin;
    if (length $$bin) {
	my $data = substr($$bin, 0, $len, '');
	$self->_inc_pos($len);
	substr($_[1], $offset) = $data;
	return length $data;
    }
    return 0 if $sftp->{_status} == $sftp->SSH2_FX_EOF;
    $sftp->_set_errno;
    undef;
}

sub EOF {
    my $self = $_[0];
    $self->_check or return undef;
    my $sftp = $self->_sftp;
    my $ret = $sftp->eof($self);
    $sftp->_set_errno unless defined $ret;
    $ret;
}

*GETC = $gen_proxy_method->('getc');
*TELL = $gen_proxy_method->('tell');
*SEEK = $gen_proxy_method->('seek');
*CLOSE = $gen_proxy_method->('close');

my $readline = $gen_proxy_method->('readline');
sub READLINE { $readline->($_[0], $/) }

sub OPEN {
    shift->CLOSE;
    undef;
}

sub DESTROY {
    local ($@, $!, $?);
    my $self = shift;
    my $sftp = $self->_sftp;
    $debug and $debug & 4 and Net::SFTP::Foreign::_debug("$self->DESTROY called (sftp: ".($sftp||'<undef>').")");
    if ($self->_check and $sftp) {
        local $sftp->{_autodie};
	$sftp->_with_save_error(close => $self);
    }
}

package Net::SFTP::Foreign::DirHandle;
our @ISA = qw(Net::SFTP::Foreign::Handle IO::Dir);

sub _new_from_rid {
    my $class = shift;
    my $sftp = shift;
    my $rid = shift;
    my $flags = shift;

    my $self = $class->SUPER::_new_from_rid($sftp, $rid, $flags, []);
}


sub _check_is_dir {}

sub _cache { *{shift()}{ARRAY}[4] }

sub DESTROY {
    local ($@, $!, $?);
    my $self = shift;
    my $sftp = $self->_sftp;

    $debug and $debug & 4 and Net::SFTP::Foreign::_debug("$self->DESTROY called (sftp: ".($sftp||'').")");

    if ($self->_check and $sftp) {
        local $sftp->{_autodie};
        $sftp->_with_save_error(closedir => $self);
    }
}

1;
__END__

=head1 NAME

Net::SFTP::Foreign - SSH File Transfer Protocol client

=head1 SYNOPSIS

    use Net::SFTP::Foreign;
    my $sftp = Net::SFTP::Foreign->new($host);
    $sftp->die_on_error("Unable to establish SFTP connection");

    $sftp->setcwd($path) or die "unable to change cwd: " . $sftp->error;

    $sftp->get("foo", "bar") or die "get failed: " . $sftp->error;

    $sftp->put("bar", "baz") or die "put failed: " . $sftp->error;

=head1 DESCRIPTION

SFTP stands for SSH File Transfer Protocol and is a method of
transferring files between machines over a secure, encrypted
connection (as opposed to regular FTP, which functions over an
insecure connection). The security in SFTP comes through its
integration with SSH, which provides an encrypted transport layer over
which the SFTP commands are executed.

Net::SFTP::Foreign is a Perl client for the SFTP version 3 as defined
in the SSH File Transfer Protocol IETF draft, which can be found at
L<http://www.openssh.org/txt/draft-ietf-secsh-filexfer-02.txt> (also
included on this package distribution, on the C<rfc> directory).

Net::SFTP::Foreign uses any compatible C<ssh> command installed on
the system (for instance, OpenSSH C<ssh>) to establish the secure
connection to the remote server.

A wrapper module L<Net::SFTP::Foreign::Compat> is also provided for
compatibility with L<Net::SFTP>.


=head2 Net::SFTP::Foreign Vs. Net::SFTP Vs. Net::SSH2::SFTP

Why should I prefer Net::SFTP::Foreign over L<Net::SFTP>?

Well, both modules have their pros and cons:

Net::SFTP::Foreign does not require a bunch of additional modules and
external libraries to work, just the OpenBSD SSH client (or any other
client compatible enough).

I trust OpenSSH SSH client more than L<Net::SSH::Perl>, there are lots
of paranoid people ensuring that OpenSSH doesn't have security
holes!!!

If you have an SSH infrastructure already deployed, by using the same
binary SSH client, Net::SFTP::Foreign ensures a seamless integration
within your environment (configuration files, keys, etc.).

Net::SFTP::Foreign is much faster transferring files, specially over
networks with high (relative) latency.

Net::SFTP::Foreign provides several high level methods not available
from Net::SFTP as for instance C<find>, C<glob>, C<rget>, C<rput>,
C<rremove>, C<mget>, C<mput>.

On the other hand, using the external command means an additional
proccess being launched and running, depending on your OS this could
eat more resources than the in process pure perl implementation
provided by L<Net::SSH::Perl>.

L<Net::SSH2> is a module wrapping libssh2, an SSH version 2 client
library written in C. It is a very active project that aims to replace
L<Net::SSH::Perl>. Unfortunately, libssh2 SFTP functionality
(available in Perl via L<Net::SSH2::SFTP>) is rather limited and its
performance very poor.

Later versions of Net::SFTP::Foreign can use L<Net::SSH2> as the
transport layer via the backend module
L<Net::SFTP::Foreign::Backend::Net_SSH2>.

=head2 Error handling

Most of the methods available from this package return undef on
failure and a true value or the requested data on
success. C<$sftp-E<gt>error> should be used to check for errors
explicitly after every method call. For instance:

  $sftp = Net::SFTP::Foreign->new($host);
  $sftp->error and die "unable to connect to remote host: " . $sftp->error;

Also, the L</die_on_error> method provides a handy shortcut for the last line:

  $sftp = Net::SFTP::Foreign->new($host);
  $sftp->die_on_error("unable to connect to remote host");

Alternatively, the C<autodie> mode that makes the module die when any
error is found can be activated from the constructor. For instance:

  $sftp = Net::SFTP::Foreign->new($host, autodie => 1);
  my $ls = $sftp->ls("/bar");
  # dies as: "Couldn't open remote dir '/bar': No such file"

The C<autodie> mode will be disabled when an C<on_error> handler is
passed to methods accepting it:

  my $sftp = Net::SFTP::Foreign->new($host, autodie => 1);
  # prints "foo!" and does not die:
  $sftp->find("/sdfjkalshfl", # nonexistent directory
              on_error => sub { print "foo!\n" });
  # dies:
  $sftp->find("/sdfjkalshfl");

=head2 API

The methods available from this module are described below.

Don't forget to read also the FAQ and BUGS sections at the end of this
document!

=over 4

=item Net::SFTP::Foreign->new($host, %args)

=item Net::SFTP::Foreign->new(%args)

Opens a new SFTP connection with a remote host C<$host>, and returns a
Net::SFTP::Foreign object representing that open connection.

An explicit check for errors should be included always after the
constructor call:

  my $sftp = Net::SFTP::Foreign->new(...);
  $sftp->die_on_error("SSH connection failed");

The optional arguments accepted are as follows:

=over 4

=item host =E<gt> $hostname

remote host name

=item user =E<gt> $username

username to log in to the remote server. This should be your SSH
login, and can be empty, in which case the username is drawn from the
user executing the process.

=item port =E<gt> $portnumber

port number where the remote SSH server is listening

=item ssh1 =E<gt> 1

use old SSH1 approach for starting the remote SFTP server.

=item more =E<gt> [@more_ssh_args]

additional args passed to C<ssh> command.

For debugging purposes you can run C<ssh> in verbose mode passing it
the C<-v> option:

  my $sftp = Net::SFTP::Foreign->new($host, more => '-v');

Note that this option expects a single command argument or a reference
to an array of arguments. For instance:

  more => '-v'         # right
  more => ['-v']       # right
  more => "-c $cipher"    # wrong!!!
  more => [-c => $cipher] # right

=item timeout =E<gt> $seconds

when this parameter is set, the connection is dropped if no data
arrives on the SSH socket for the given time while waiting for some
command to complete.

When the timeout expires, the current method is aborted and
the SFTP connection becomes invalid.

=item fs_encoding =E<gt> $encoding

Version 3 of the SFTP protocol (the one supported by this module)
knows nothing about the character encoding used on the remote
filesystem to represent file and directory names.

This option allows one to select the encoding used in the remote
machine. The default value is C<utf8>.

For instance:

  $sftp = Net::SFTP::Foreign->new('user@host', fs_encoding => 'latin1');

will convert any path name passed to any method in this package to its
C<latin1> representation before sending it to the remote side.

Note that this option will not affect file contents in any way.

This feature is not supported in perl 5.6 due to incomplete Unicode
support in the interpreter.

=item key_path =E<gt> $filename

=item key_path =E<gt> \@filenames

asks C<ssh> to use the key(s) in the given file(s) for authentication.

=item password =E<gt> $password

Logs into the remote host using password authentication with the given
password.

Password authentication is only available if the module L<IO::Pty> is
installed. Note also, that on Windows this module is only available
when running the Cygwin port of Perl.

=item asks_for_username_at_login =E<gt> 0|'auto'|1

During the interactive authentication dialog, most SSH servers only
ask for the user password as the login name is passed inside the SSH
protocol. But under some uncommon servers or configurations it is
possible that a username is also requested.

When this flag is set to C<1>, the username will be send
inconditionally at the first remote prompt and then the password at
the second.

When it is set to C<auto> the module will use some heuristics in order
to determine if it is being asked for an username.

When set to C<0>, the username will never be sent during the
authentication dialog. This is the default.

=item passphrase =E<gt> $passphrase

Logs into the remote server using a passphrase protected private key.

Requires also the module L<IO::Pty>.

=item expect_log_user =E<gt> $bool

This feature is obsolete as Expect is not used anymore to handle
password authentication.

=item ssh_cmd =E<gt> $sshcmd

=item ssh_cmd =E<gt> \@sshcmd

name of the external SSH client. By default C<ssh> is used.

For instance:

  $sftp = Net::SFTP::Foreign->new($host, ssh_cmd => 'plink');

When an array reference is used, its elements are inserted at the
beginning of the system call. That allows, for instance, to connect to
the target host through some SSH proxy:

  $sftp = Net::SFTP::Foreign->new($host,
              ssh_cmd => qw(ssh -l user proxy.server ssh));

But note that the module will not handle password authentication for
those proxies.

=item ssh_cmd_interface =E<gt> 'plink' or 'ssh' or 'tectia'

declares the command line interface that the SSH client used to
connect to the remote host understands. Currently C<plink>, C<ssh> and
C<tectia> are supported.

This option would be rarely required as the module infers the
interface from the SSH command name.

=item transport =E<gt> $fh

=item transport =E<gt> [$in_fh, $out_fh]

=item transport =E<gt> [$in_fh, $out_fh, $pid]

allows one to use an already open pipe or socket as the transport for
the SFTP protocol.

It can be (ab)used to make this module work with password
authentication or with keys requiring a passphrase.

C<in_fh> is the file handler used to read data from the remote server,
C<out_fh> is the file handler used to write data.

On some systems, when using a pipe as the transport, closing it, does
not cause the process at the other side to exit. The additional
C<$pid> argument can be used to instruct this module to kill that
process if it doesn't exit by itself.

=item open2_cmd =E<gt> [@cmd]

=item open2_cmd =E<gt> $cmd;

allows one to completely redefine how C<ssh> is called. Its arguments
are passed to L<IPC::Open2::open2> to open a pipe to the remote
server.

=item stderr_fh =E<gt> $fh

redirects the output sent to stderr by the SSH subprocess to the given
file handle.

It can be used to suppress banners:

  open my $ssherr, '>', '/dev/null' or die "unable to open /dev/null";
  my $sftp = Net::SFTP::Foreign->new($host,
                                     stderr_fh => $ssherr);

Or to send SSH stderr to a file in order to capture errors for later
analysis:

  my $ssherr = File::Temp->new or die "File::Temp->new failed";
  my $sftp = Net::SFTP::Foreign->new($hostname, more => ['-v'],
                                     stderr_fh => $ssherr);
  if ($sftp->error) {
    print "sftp error: ".$sftp->error."\n";
    seek($ssherr, 0, 0);
    while (<$ssherr>) {
      print "captured stderr: $_";
    }
  }

=item stderr_discard =E<gt> 1

redirects stderr to /dev/null

=item block_size =E<gt> $default_block_size

=item queue_size =E<gt> $default_queue_size

default C<block_size> and C<queue_size> used for read and write
operations (see the C<put> or C<get> documentation).

=item autoflush =E<gt> $bool

by default, and for performance reasons, write operations are cached,
and only when the write buffer becomes big enough is the data written to
the remote file. Setting this flag makes the write operations inmediate.

=item write_delay =E<gt> $bytes

This option determines how many bytes are buffered before the real
SFTP write operation is performed.

=item read_ahead =E<gt> $bytes

On read operations this option determines how many bytes to read in
advance so that later read operations can be fulfilled from the
buffer.

Using a high value will increase the performance of the module for a
sequential reads access pattern but degrade it for a short random
reads access pattern. It can also cause synchronization problems if
the file is concurrently modified by other parties (L</flush> can be
used to discard all the data inside the read buffer on demand).

The default value is set dynamically considering some runtime
parameters and given options, though it tends to favor the sequential
read access pattern.

=item autodisconnect =E<gt> $ad

by default, the SSH connection is closed from the DESTROY method when
the object goes out of scope. But on scripts that fork new processes,
that results on the SSH connection being closed by the first process
where the object goes out of scope, something undesirable.

This option allows one to work-around this issue to some extend.

The acceptable values for C<$ad> are:

=over 4

=item 0

Never try to disconnect this object when exiting from any process.

On most operating systems, the SSH process will exit when the last
process connected to it ends, but this is not guaranteed.

=item 1

Disconnect on exit from any process. This is the default.

=item 2

Disconnect on exit from the current process only.

=back

See also the disconnect and autodisconnect methods.

=item late_set_perm =E<gt> $bool

See the FAQ below.

=item dirty_cleanup =E<gt> $bool

Sets the C<dirty_cleanup> flag in a per object basis (see the BUGS
section).

=item backend => $backend

From version 1.57 Net::SFTP::Foreign supports plugable backends in
order to allow other ways to comunicate with the remote server in
addition to the default I<pipe-to-ssh-process>.

Custom backends may change the set of options supported by the C<new>
method.

=item autodie => $bool

Enables the autodie mode that will cause the module to die when any
error is found (a la L<autodie>).

=back

=item $sftp-E<gt>error

Returns the error code from the last executed command. The value
returned is similar to C<$!>, when used as a string it yields the
corresponding error string.

See L<Net::SFTP::Foreign::Constants> for a list of possible error
codes and how to import them on your scripts.

=item $sftp-E<gt>die_on_error($msg)

Convenience method:

  $sftp->die_on_error("Something bad happened");
  # is a shortcut for...
  $sftp->error and die "Something bad happened: " . $sftp->error;

=item $sftp-E<gt>status

Returns the code from the last SSH2_FXP_STATUS response. It is also a
dualvar that yields the status string when used as a string.

Usually C<$sftp-E<gt>error> should be checked first to see if there was
any error and then C<$sftp-E<gt>status> to find out its low level cause.

=item $sftp-E<gt>cwd

Returns the remote current working directory.

When a relative remote path is passed to any of the methods on this
package, this directory is used to compose the absolute path.

=item $sftp-E<gt>setcwd($dir)

Changes the remote current working directory. The remote directory
should exist, otherwise the call fails.

Returns the new remote current working directory or undef on failure.

=item $sftp-E<gt>get($remote, $local, %options)

X<get>Copies remote file C<$remote> to local $local. By default file
attributes are also copied (permissions, atime and mtime). For
instance:

  $sftp->get('/var/log/messages', /tmp/messages')
    or die "file transfer failed: " . $sftp->error;

A file handle can also be used as the local target. In that case, the
remote file contents are retrieved and written to the given file
handle. Note also that the handle is not closed when the transmission
finish.

  open F, '| gzip -c > /tmp/foo' or die ...;
  $sftp->get("/etc/passwd", \*F)
    or die "get failed: " . $sftp->error;
  close F or die ...;

Accepted options (not all combinations are possible):

=over 4

=item copy_time =E<gt> $bool

determines if access and modification time attributes have to be
copied from remote file. Default is to copy them.

=item copy_perm =E<gt> $bool

determines if permision attributes have to be copied from remote
file. Default is to copy them after applying the local process umask.

=item umask =E<gt> $umask

allows one to select the umask to apply when setting the permissions
of the copied file. Default is to use the umask for the current
process or C<0> if the C<perm> option is algo used.

=item perm =E<gt> $perm

sets the permision mask of the file to be $perm, remote
permissions are ignored.

=item resume =E<gt> 1 | 'auto'

resumes an interrupted transfer.

If the C<auto> value is given, the transfer will be resumed only when
the local file is newer than the remote one.

C<get> transfers can not be resumed when a data conversion is in
place.

=item append =E<gt> 1

appends the contents of the remote file at the end of the local one
instead of overwriting it. If the local file does not exist a new one
is created.

=item overwrite =E<gt> 0

setting this option to zero cancels the transfer when a local file of
the same name already exists.

=item numbered =E<gt> 1

modifies the local file name inserting a sequence number when required
in order to avoid overwriting local files.

For instance:

  for (1..2) {
    $sftp->get("data.txt", "data.txt", numbered => 1);
  }

will copy the remote file as "data.txt" the first time and as
"data(1).txt" the second one.

If a scalar reference is passed as the numbered value, the final
target will be stored in the value pointed by the reference. For
instance:

  my $target;
  $sftp->get("data.txt", "data.txt", numbered => \$target);
  say "file was saved as $target" unless $sftp->error

=item atomic =E<gt> 1

The remote file contents are transferred into a temporal file that
once the copy completes is renamed to the target destination.

If not-overwrite of remote files is also requested, an empty file may
appear at the target destination before the rename operation is
performed. This is due to limitations of some operating/file systems.

=item cleanup =E<gt> 1

If the transfer fails, remove the incomplete file.

This option is set to by default when there is not possible to resume
the transfer afterwards (i.e., when using `atomic` or `numbered`
options).

=item best_effort =E<gt> 1

Ignore minor errors as setting time or permissions.

=item conversion =E<gt> $conversion

on the fly data conversion of the file contents can be performed with
this option. See L</On the fly data conversion> below.

=item callback =E<gt> $callback

C<$callback> is a reference to a subroutine that will be called after
every iteration of the download process.

The callback function will receive as arguments: the current
Net::SFTP::Foreign object; the data read from the remote file; the
offset from the beginning of the file in bytes; and the total size of
the file in bytes.

This mechanism can be used to provide status messages, download
progress meters, etc.:

    sub callback {
        my($sftp, $data, $offset, $size) = @_;
        print "Read $offset / $size bytes\r";
    }

The C<abort> method can be called from inside the callback to abort
the transfer:

    sub callback {
        my($sftp, $data, $offset, $size) = @_;
        if (want_to_abort_transfer()) {
            $sftp->abort("You wanted to abort the transfer");
        }
    }

The callback will be called one last time with an empty data argument
to indicate the end of the file transfer.

The size argument can change between different calls as data is
transferred (for instance, when on-the-fly data conversion is being
performed or when the size of the file can not be retrieved with the
C<stat> SFTP command before the data transfer starts).

=item block_size =E<gt> $bytes

size of the blocks the file is being split on for transfer.
Incrementing this value can improve performance but some servers limit
the maximum size.

=item queue_size =E<gt> $size

read and write requests are pipelined in order to maximize transfer
throughput. This option allows one to set the maximum number of
requests that can be concurrently waiting for a server response.

=back

=item $sftp-E<gt>get_content($remote)

Returns the content of the remote file.

=item $sftp-E<gt>get_symlink($remote, $local, %opts)

copies a symlink from the remote server to the local file system

The accepted options are C<overwrite> and C<numbered>. They have the
same effect as for the C<get> method.

=item $sftp-E<gt>put($local, $remote, %opts)

Uploads a file C<$local> from the local host to the remote host, and
saves it as C<$remote>. By default file attributes are also
copied. For instance:

  $sftp->put("test.txt", "test.txt")
    or die "put failed: " . $sftp->error;

A file handle can also be passed in the C<$local> argument. In that
case, data is read from there and stored in the remote file. UTF8 data
is not supported unless a custom converter callback is used to
transform it to bytes and the method will croak if it encounters any
data in perl internal UTF8 format. Note also that the handle is not
closed when the transmission finish.

Example:

  binmode STDIN;
  $sftp->put(\*STDIN, "stdin.dat") or die "put failed";
  close STDIN;

This method accepts several options:

=over 4

=item copy_time =E<gt> $bool

determines if access and modification time attributes have to be
copied from remote file. Default is to copy them.

=item copy_perm =E<gt> $bool

determines if permision attributes have to be copied from remote
file. Default is to copy them after applying the local process umask.

=item umask =E<gt> $umask

allows one to select the umask to apply when setting the permissions
of the copied file. Default is to use the umask for the current
process.

=item perm =E<gt> $perm

sets the permision mask of the file to be $perm, umask and local
permissions are ignored.

=item overwrite =E<gt> 0

by default C<put> will overwrite any pre-existent file with the same
name at the remote side. Setting this flag to zero will make the
method fail in that case.

=item numbered =E<gt> 1

when required, adds a sequence number to local file names in order to
avoid overwriting pre-existent files. Off by default.

=item append =E<gt> 1

appends the local file at the end of the remote file instead of
overwriting it. If the remote file does not exist a new one is
created. Off by default.

=item resume =E<gt> 1 | 'auto'

resumes an interrupted transfer.

If the C<auto> value is given, the transfer will be resumed only when
the remote file is newer than the local one.

=item sparse =E<gt> 1

Blocks that are all zeros are skipped possibly creating an sparse file
on the remote host.

=item atomic =E<gt> 1

The local file contents are transferred into a temporal file that
once the copy completes is renamed to the target destination.

This operation relies on the SSH server to perform an
overwriting/non-overwriting atomic rename operation free of race
conditions.

OpenSSH server does it correctly on top of Linux/UNIX native file
systems (i.e. ext[234], ffs or zfs) but has problems on file systems
not supporting hard links (i.e. FAT) or on operating systems with
broken POSIX semantics as Windows.

=item cleanup =E<gt> 1

If the transfer fails, attempts to remove the incomplete file.

Cleanup may fail if for example the SSH connection gets broken.

This option is set to by default when there is not possible to resume
the transfer afterwards (i.e., when using `atomic` or `numbered`
options).

=item best_effort =E<gt> 1

Ignore minor errors, as setting time and permissions on the remote
file.

=item conversion =E<gt> $conversion

on the fly data conversion of the file contents can be performed with
this option. See L</On the fly data conversion> below.

=item callback =E<gt> $callback

C<$callback> is a reference to a subrutine that will be called after
every iteration of the upload process.

The callback function will receive as arguments: the current
Net::SFTP::Foreign object; the data that is going to be written to the
remote file; the offset from the beginning of the file in bytes; and
the total size of the file in bytes.

The callback will be called one last time with an empty data argument
to indicate the end of the file transfer.

The size argument can change between calls as data is transferred (for
instance, when on the fly data conversion is being performed).

This mechanism can be used to provide status messages, download
progress meters, etc.

The C<abort> method can be called from inside the callback to abort
the transfer.

=item block_size =E<gt> $bytes

size of the blocks the file is being split on for transfer.
Incrementing this value can improve performance but some servers limit
its size and if this limit is overpassed the command will fail.

=item queue_size =E<gt> $size

read and write requests are pipelined in order to maximize transfer
throughput. This option allows one to set the maximum number of
requests that can be concurrently waiting for a server response.

=item late_set_perm =E<gt> $bool

See the FAQ below.

=back

=item $sftp-E<gt>put_symlink($local, $remote, %opts)

copies a local symlink to the remote host.

The accepted options are C<overwrite> and C<numbered>.

=item $sftp-E<gt>abort()

=item $sftp-E<gt>abort($msg)

This method, when called from inside a callback sub, causes the
current transfer to be aborted

The error state is set to SFTP_ERR_ABORTED and the optional $msg
argument is used as its textual value.

=item $sftp-E<gt>ls($remote, %opts)

Fetches a listing of the remote directory C<$remote>. If C<$remote> is
not given, the current remote working directory is listed.

Returns a reference to a list of entries. Every entry is a reference
to a hash with three keys: C<filename>, the name of the entry;
C<longname>, an entry in a "long" listing like C<ls -l>; and C<a>, a
L<Net::SFTP::Foreign::Attributes> object containing file atime, mtime,
permissions and size.

    my $ls = $sftp->ls('/home/foo')
        or die "unable to retrieve directory: ".$sftp->error;

    print "$_->{filename}\n" for (@$ls);



The options accepted by this method are as follows (note that usage of
some of them can degrade the method performance when reading large
directories):

=over 4

=item wanted =E<gt> qr/.../

Only elements whose filename matchs the regular expression are included
on the listing.

=item wanted =E<gt> sub {...}

Only elements for which the callback returns a true value are included
on the listing. The callback is called with two arguments: the
C<$sftp> object and the current entry (a hash reference as described
before). For instance:

  use Fcntl ':mode';

  my $files = $sftp->ls ( '/home/hommer',
			  wanted => sub {
			      my $entry = $_[1];
			      S_ISREG($entry->{a}->perm)
			  } )
	or die "ls failed: ".$sftp->error;


=item no_wanted =E<gt> qr/.../

=item no_wanted =E<gt> sub {...}

those options have the oposite result to their C<wanted> counterparts:

  my $no_hidden = $sftp->ls( '/home/homer',
			     no_wanted => qr/^\./ )
	or die "ls failed";


When both C<no_wanted> and C<wanted> rules are used, the C<no_wanted>
rule is applied first and then the C<wanted> one (order is important
if the callbacks have side effects, experiment!).

=item ordered =E<gt> 1

the list of entries is ordered by filename.

=item follow_links =E<gt> 1

by default, the attributes on the listing correspond to a C<lstat>
operation, setting this option causes the method to perform C<stat>
requests instead. C<lstat> attributes will stil appear for links
pointing to non existant places.

=item atomic_readdir =E<gt> 1

reading a directory is not an atomic SFTP operation and the protocol
draft does not define what happens if C<readdir> requests and write
operations (for instance C<remove> or C<open>) affecting the same
directory are intermixed.

This flag ensures that no callback call (C<wanted>, C<no_wanted>) is
performed in the middle of reading a directory and has to be set if
any of the callbacks can modify the file system.

=item realpath =E<gt> 1

for every file object, performs a realpath operation and populates the
C<realpath> entry.

=item names_only =E<gt> 1

makes the method return a simple array containing the file names from
the remote directory only. For instance, these two sentences are
equivalent:

  my @ls1 = @{ $sftp->ls('.', names_only => 1) };

  my @ls2 = map { $_->{filename} } @{$sftp->ls('.')};

=back

=item $sftp-E<gt>find($path, %opts)

=item $sftp-E<gt>find(\@paths, %opts)

X<find>Does a recursive search over the given directory C<$path> (or
directories C<@path>) and returns a list of the entries found or the
total number of them on scalar context.

Every entry is a reference to a hash with two keys: C<filename>, the
full path of the entry; and C<a>, a L<Net::SFTP::Foreign::Attributes>
object containing file atime, mtime, permissions and size.

This method tries to recover and continue under error conditions.

The options accepted:

=over 4

=item on_error =E<gt> sub { ... }

the callback is called when some error is detected, two arguments are
passed: the C<$sftp> object and the entry that was being processed
when the error happened. For instance:

  my @find = $sftp->find( '/',
			  on_error => sub {
			      my ($sftp, $e) = @_;
		 	      print STDERR "error processing $e->{filename}: "
				   . $sftp->error;
			  } );

=item realpath =E<gt> 1

calls method C<realpath> for every entry, the result is stored under
the key C<realpath>. This option slows down the process as a new
remote query is performed for every entry, specially on networks with
high latency.

=item follow_links =E<gt> 1

By default symbolic links are not resolved and appear as that on the
final listing. This option causes then to be resolved and substituted
by the target file system object. Dangling links are ignored, though
they generate a call to the C<on_error> callback when stat'ing them
fails.

Following sym links can introduce loops on the search. Infinite loops
are detected and broken but files can still appear repeated on the
final listing under different names unless the option C<realpath> is
also actived.

=item ordered =E<gt> 1

By default, the file system is searched in an implementation dependent
order (actually optimized for low memory comsumption). If this option
is included, the file system is searched in a deep-first, sorted by
filename fashion.

=item wanted =E<gt> qr/.../

=item wanted =E<gt> sub { ... }

=item no_wanted =E<gt> qr/.../

=item no_wanted =E<gt> sub { ... }

These options have the same effect as on the C<ls> method, allowing to
filter out unwanted entries (note that filename keys contain B<full
paths> here).

The callbacks can also be used to perform some action instead of
creating the full listing of entries in memory (that could use huge
amounts of RAM for big file trees):

  $sftp->find($src_dir,
	      wanted => sub {
		  my $fn = $_[1]->{filename}
		  print "$fn\n" if $fn =~ /\.p[ml]$/;
		  return undef # so it is discarded
	      });

=item descend =E<gt> qr/.../

=item descend =E<gt> sub { ... }

=item no_descend =E<gt> qr/.../

=item no_descend =E<gt> sub { ... }

These options, similar to the C<wanted> ones, allow to prune the
search, discarding full subdirectories. For instance:

    use Fcntl ':mode';
    my @files = $sftp->find( '.',
			     no_descend => qr/\.svn$/,
			     wanted => sub {
				 S_ISREG($_[1]->{a}->perm)
			     } );


C<descend> and C<wanted> rules are unrelated. A directory discarded by
a C<wanted> rule will still be recursively searched unless it is also
discarded on a C<descend> rule and vice-versa.

=item atomic_readdir =E<gt> 1

see C<ls> method documentation.

=item names_only =E<gt> 1

makes the method return a list with the names of the files only (see C<ls>
method documentation).

equivalent:

  my $ls1 = $sftp->ls('.', names_only => 1);

=back

=item $sftp-E<gt>glob($pattern, %opts)

X<glob>performs a remote glob and returns the list of matching entries
in the same format as the L</find> method.

This method tries to recover and continue under error conditions.

The given pattern can be a Unix style pattern (see L<glob(7)>) or a
Regexp object (i.e C<qr/foo/>). In the later case, only files on the
current working directory will be matched against the Regexp.

Accepted options:

=over 4

=item ignore_case =E<gt> 1

by default the matching over the file system is carried out in a case
sensitive fashion, this flag changes it to be case insensitive.

This flag is ignored when a Regexp object is used as the pattern.

=item strict_leading_dot =E<gt> 0

by default, a dot character at the beginning of a file or directory
name is not matched by willcards (C<*> or C<?>). Setting this flags to
a false value changes this behaviour.

This flag is ignored when a Regexp object is used as the pattern.

=item follow_links =E<gt> 1

=item ordered =E<gt> 1

=item names_only =E<gt> 1

=item realpath =E<gt> 1

=item on_error =E<gt> sub { ... }

=item wanted =E<gt> ...

=item no_wanted =E<gt> ...

these options perform as on the C<ls> method.

=back

Some usage samples:

  my $files = $sftp->glob("*/lib");

  my $files = $sftp->glob("/var/log/dmesg.*.gz");

  $sftp->set_cwd("/var/log");
  my $files = $sftp->glob(qr/^dmesg\.[\d+]\.gz$/);

  my $files = $sftp->glob("*/*.pdf", strict_leading_dot => 0);

=item $sftp-E<gt>rget($remote, $local, %opts)

Recursively copies the contents of remote directory C<$remote> to
local directory C<$local>. Returns the total number of elements
(files, dirs and symbolic links) successfully copied.

This method tries to recover and continue when some error happens.

The options accepted are:

=over 4

=item umask =E<gt> $umask

use umask C<$umask> to set permissions on the files and directories
created.

=item copy_perm =E<gt> $bool;

if set to a true value, file and directory permissions are copied to
the remote server (after applying the umask). On by default.

=item copy_time =E<gt> $bool;

if set to a true value, file atime and mtime are copied from the
remote server. By default it is on.

=item overwrite =E<gt> $bool

if set to a true value, when a local file with the same name
already exists it is overwritten. On by default.

=item numbered =E<gt> $bool

when required, adds a sequence number to local file names in order to
avoid overwriting pre-existent remote files. Off by default.

=item newer_only =E<gt> $bool

if set to a true value, when a local file with the same name
already exists it is overwritten only if the remote file is newer.

=item ignore_links =E<gt> $bool

if set to a true value, symbolic links are not copied.

=item on_error =E<gt> sub { ... }

the passed sub is called when some error happens. It is called with two
arguments, the C<$sftp> object and the entry causing the error.

=item wanted =E<gt> ...

=item no_wanted =E<gt> ...

This option allows one to select which files and directories have to
be copied. See also C<ls> method docs.

If a directory is discarded all of its contents are also discarded (as
it is not possible to copy child files without creating the directory
first!).

=item atomic =E<gt> 1

=item block_size =E<gt> $block_size

=item queue_size =E<gt> $queue_size

=item conversion =E<gt> $conversion

=item resume =E<gt> $resume

=item best_effort =E<gt> $best_effort

See C<get> method docs.

=back

=item $sftp-E<gt>rput($local, $remote, %opts)

Recursively copies the contents of local directory C<$local> to
remote directory C<$remote>.

This method tries to recover and continue when some error happens.

Accepted options are:

=over 4

=item umask =E<gt> $umask

use umask C<$umask> to set permissions on the files and directories
created.

=item copy_perm =E<gt> $bool;

if set to a true value, file and directory permissions are copied
to the remote server (after applying the umask). On by default.

=item copy_time =E<gt> $bool;

if set to a true value, file atime and mtime are copied to the
remote server. On by default.

=item overwrite =E<gt> $bool

if set to a true value, when a remote file with the same name already
exists it is overwritten. On by default.

=item newer_only =E<gt> $bool

if set to a true value, when a remote file with the same name already exists it is
overwritten only if the local file is newer.

=item ignore_links =E<gt> $bool

if set to a true value, symbolic links are not copied

=item on_error =E<gt> sub { ... }

the passed sub is called when some error happens. It is called with two
arguments, the C<$sftp> object and the entry causing the error.

=item wanted =E<gt> ...

=item no_wanted =E<gt> ...

This option allows one to select which files and directories have to
be copied. See also C<ls> method docs.

If a directory is discarded all of its contents are also discarded (as
it is not possible to copy child files without creating the directory
first!).

=item atomic =E<gt> 1

=item block_size =E<gt> $block_size

=item queue_size =E<gt> $queue_size

=item conversion =E<gt> $conversion

=item resume =E<gt> $resume

=item best_effort =E<gt> $best_effort

=item late_set_perm =E<gt> $bool

see C<put> method docs.

=back

=item $sftp-E<gt>rremove($dir, %opts)

=item $sftp-E<gt>rremove(\@dirs, %opts)

recursively remove directory $dir (or directories @dirs) and its
contents. Returns the number of elements successfully removed.

This method tries to recover and continue when some error happens.

The options accepted are:

=over 4

=item on_error =E<gt> sub { ... }

This callback is called when some error is occurs. The arguments
passed are the C<$sftp> object and the current entry (see C<ls> docs
for more information).

=item wanted =E<gt> ...

=item no_wanted =E<gt> ...

Allow to select which file system objects have to be deleted.

=back

=item $sftp-E<gt>mget($remote, $localdir, %opts)

=item $sftp-E<gt>mget(\@remote, $localdir, %opts)

X<mget>expands the wildcards on C<$remote> or C<@remote> and retrieves
all the matching files.

For instance:

  $sftp->mget(['/etc/hostname.*', '/etc/init.d/*'], '/tmp');

The method accepts all the options valid for L</glob> and for L</get>
(except those that do not make sense :-)

C<$localdir> is optional and defaults to the process cwd.

Files are saved with the same name they have in the remote server
excluding the directory parts.

Note that name collisions are not detected. For instance:

 $sftp->mget(["foo/file.txt", "bar/file.txt"], "/tmp")

will transfer the first file to "/tmp/file.txt" and later overwrite it
with the second one. The C<numbered> option can be used to avoid this
issue.

=item $sftp-E<gt>mput($local, $remotedir, %opts)

=item $sftp-E<gt>mput(\@local, $remotedir, %opts)

similar to L</mget> but works in the opposite direction transferring
files from the local side to the remote one.

=item $sftp-E<gt>join(@paths)

returns the given path fragments joined in one path (currently the
remote file system is expected to be Unix like).

=item $sftp-E<gt>open($path, $flags [, $attrs ])

Sends the C<SSH_FXP_OPEN> command to open a remote file C<$path>,
and returns an open handle on success. On failure returns
C<undef>.

The returned value is a tied handle (see L<Tie::Handle>) that can be
used to access the remote file both with the methods available from
this module and with perl built-ins. For instance:

  # reading from the remote file
  my $fh1 = $sftp->open("/etc/passwd")
    or die $sftp->error;
  while (<$fh1>) { ... }

  # writing to the remote file
  use Net::SFTP::Foreign::Constants qw(:flags);
  my $fh2 = $sftp->open("/foo/bar", SSH2_FXF_WRITE|SSH2_FXF_CREAT)
    or die $sftp->error;
  print $fh2 "printing on the remote file\n";
  $sftp->write($fh2, "writing more");

The C<$flags> bitmap determines how to open the remote file as defined
in the SFTP protocol draft (the following constants can be imported
from L<Net::SFTP::Foreign::Constants>):

=over 4

=item SSH2_FXF_READ

Open the file for reading. It is the default mode.

=item SSH2_FXF_WRITE

Open the file for writing.  If both this and C<SSH2_FXF_READ> are
specified, the file is opened for both reading and writing.

=item SSH2_FXF_APPEND

Force all writes to append data at the end of the file.

As OpenSSH SFTP server implementation ignores this flag, the module
emulates it (I will appreciate receiving feedback about the
interoperation of this module with other server implementations when
this flag is used).

=item SSH2_FXF_CREAT

If this flag is specified, then a new file will be created if one does
not already exist.

=item SSH2_FXF_TRUNC

Forces an existing file with the same name to be truncated to zero
length when creating a file. C<SSH2_FXF_CREAT> must also be specified
if this flag is used.

=item SSH2_FXF_EXCL

Causes the request to fail if the named file already exists.
C<SSH2_FXF_CREAT> must also be specified if this flag is used.

=back

When creating a new remote file, C<$attrs> allows one to set its
initial attributes. C<$attrs> has to be an object of class
L<Net::SFTP::Foreign::Attributes>.

=item $sftp-E<gt>close($handle)

Closes the remote file handle C<$handle>.

Files are automatically closed on the handle C<DESTROY> method when
not done explicitelly.

Returns true on success and undef on failure.

=item $sftp-E<gt>read($handle, $length)

reads C<$length> bytes from an open file handle C<$handle>. On success
returns the data read from the remote file and undef on failure
(including EOF).

=item $sftp-E<gt>write($handle, $data)

writes C<$data> to the remote file C<$handle>. Returns the number of
bytes written or undef on failure.

=item $sftp-E<gt>readline($handle)

=item $sftp-E<gt>readline($handle, $sep)

in scalar context reads and returns the next line from the remote
file. In list context, it returns all the lines from the current
position to the end of the file.

By default "\n" is used as the separator between lines, but a
different one can be used passing it as the second method argument. If
the empty string is used, it returns all the data from the current
position to the end of the file as one line.

=item $sftp-E<gt>getc($handle)

returns the next character from the file.

=item $sftp-E<gt>seek($handle, $pos, $whence)

sets the current position for the remote file handle C<$handle>. If
C<$whence> is 0, the position is set relative to the beginning of the
file; if C<$whence> is 1, position is relative to current position and
if $<$whence> is 2, position is relative to the end of the file.

returns a trues value on success, undef on failure.

=item $sftp-E<gt>tell($fh)

returns the current position for the remote file handle C<$handle>.

=item $sftp-E<gt>eof($fh)

reports whether the remote file handler points at the end of the file.

=item $sftp-E<gt>flush($fh)

X<flush>writes to the remote file any pending data and discards the read
cache.

=item $sftp-E<gt>sftpread($handle, $offset, $length)

low level method that sends a SSH2_FXP_READ request to read from an
open file handle C<$handle>, C<$length> bytes starting at C<$offset>.

Returns the data read on success and undef on failure.

Some servers (for instance OpenSSH SFTP server) limit the size of the
read requests and so the length of data returned can be smaller than
requested.

=item $sftp-E<gt>sftpwrite($handle, $offset, $data)

low level method that sends a C<SSH_FXP_WRITE> request to write to an
open file handle C<$handle>, starting at C<$offset>, and where the
data to be written is in C<$data>.

Returns true on success and undef on failure.

=item $sftp-E<gt>opendir($path)

Sends a C<SSH_FXP_OPENDIR> command to open the remote directory
C<$path>, and returns an open handle on success (unfortunately,
current versions of perl does not support directory operations via
tied handles, so it is not possible to use the returned handle as a
native one).

On failure returns C<undef>.

=item $sftp-E<gt>closedir($handle)

closes the remote directory handle C<$handle>.

Directory handles are closed from their C<DESTROY> method when not
done explicitly.

Return true on success, undef on failure.

=item $sftp-E<gt>readdir($handle)

returns the next entry from the remote directory C<$handle> (or all
the remaining entries when called in list context).

The return values are a hash with three keys: C<filename>, C<longname> and
C<a>. The C<a> value contains a L<Net::SFTP::Foreign::Attributes>
object describing the entry.

Returns undef on error or when no more entries exist on the directory.

=item $sftp-E<gt>stat($path_or_fh)

performs a C<stat> on the remote file and returns a
L<Net::SFTP::Foreign::Attributes> object with the result values. Both
paths and open remote file handles can be passed to this method.

Returns undef on failure.

=item $sftp-E<gt>lstat($path)

this method is similar to C<stat> method but stats a symbolic link
instead of the file the symbolic links points to.

=item $sftp-E<gt>setstat($path_or_fh, $attrs)

sets file attributes on the remote file. Accepts both paths and open
remote file handles.

Returns true on success and undef on failure.

=item $sftp-E<gt>truncate($path_or_fh, $size)

=item $sftp-E<gt>chown($path_or_fh, $uid, $gid)

=item $sftp-E<gt>chmod($path_or_fh, $perm)

=item $sftp-E<gt>utime($path_or_fh, $atime, $mtime)

Shortcuts around setstat.

=item $sftp-E<gt>remove($path)

Sends a C<SSH_FXP_REMOVE> command to remove the remote file
C<$path>. Returns a true value on success and undef on failure.

=item $sftp-E<gt>mkdir($path)

=item $sftp-E<gt>mkdir($path, $attrs)

Sends a C<SSH_FXP_MKDIR> command to create a remote directory C<$path>
whose attributes are initialized to C<$attrs> (a
L<Net::SFTP::Foreign::Attributes> object) if given.

Returns a true value on success and undef on failure.

=item $sftp-E<gt>mkpath($path)

=item $sftp-E<gt>mkpath($path, $attrs)

This method is similar to C<mkdir> but also creates any non-existant
parent directories recursively.

=item $sftp-E<gt>rmdir($path)

Sends a C<SSH_FXP_RMDIR> command to remove a remote directory
C<$path>. Returns a true value on success and undef on failure.

=item $sftp-E<gt>realpath($path)

Sends a C<SSH_FXP_REALPATH> command to canonicalise C<$path>
to an absolute path. This can be useful for turning paths
containing C<'..'> into absolute paths.

Returns the absolute path on success, C<undef> on failure.

=item $sftp-E<gt>rename($old, $new, %opts)

Sends a C<SSH_FXP_RENAME> command to rename C<$old> to C<$new>.
Returns a true value on success and undef on failure.

Accepted options are:

=over 4

=item overwrite => $bool

By default, the rename operation fails when a file C<$new> already
exists. When this options is set, any previous existant file is
deleted first (the C<atomic_rename> operation will be used if
available).

Note than under some conditions the target file could be deleted and
afterwards the rename operation fail.

=back

=item $sftp-E<gt>atomic_rename($old, $new)

Renames a file using the C<posix-rename@openssh.com> extension when
available.

Unlike the C<rename> method, it overwrites any previous C<$new> file.

=item $sftp-E<gt>readlink($path)

Sends a C<SSH_FXP_READLINK> command to read the path where the
simbolic link is pointing.

Returns the target path on success and undef on failure.

=item $sftp-E<gt>symlink($sl, $target)

Sends a C<SSH_FXP_SYMLINK> command to create a new symbolic link
C<$sl> pointing to C<$target>.

C<$target> is stored as-is, without any path expansion taken place on
it. Use C<realpath> to normalize it:

  $sftp->symlink("foo.lnk" => $sftp->realpath("../bar"))

=item $sftp-E<gt>hardlink($hl, $target)

Creates a hardlink on the server.

This command requires support for the 'hardlink@openssh.com' extension
on the server (available in OpenSSH from version 5.7).

=item $sftp-E<gt>statvfs($path_or_fh)

On servers supporting C<statvfs@openssh.com> and
C<fstatvfs@openssh.com> extensions respectively, these methods return
a hash reference with information about the file system where the
given file named resides.

The hash entries are:

  bsize   => file system block size
  frsize  => fundamental fs block size
  blocks  => number of blocks (unit f_frsize)
  bfree   => free blocks in file system
  bavail  => free blocks for non-root
  files   => total file inodes
  ffree   => free file inodes
  favail  => free file inodes for to non-root
  fsid    => file system id
  flag    => bit mask of f_flag values
  namemax => maximum filename length

The values of the f_flag bit mask are as follows:

  SSH2_FXE_STATVFS_ST_RDONLY => read-only
  SSH2_FXE_STATVFS_ST_NOSUID => no setuid

=item $sftp-E<gt>disconnect

Closes the SSH connection to the remote host. From this point the
object becomes mostly useless.

Usually, this method should not be called explicitly, but implicitly
from the DESTROY method when the object goes out of scope.

See also the documentation for the C<autodiscconnect> constructor
argument.

=item $sftp-E<gt>autodisconnect($ad)

Sets the C<autodisconnect> behaviour.

See also the documentation for the C<autodiscconnect> constructor
argument. The values accepted here are the same as there.

=back


=head2 On the fly data conversion

Some of the methods on this module allow to perform on the fly data
conversion via the C<conversion> option that accepts the following
values:

=over 4

=item conversion =E<gt> 'dos2unix'

Converts CR+LF line endings (as commonly used under MS-DOS) to LF
(Unix).

=item conversion =E<gt> 'unix2dos'

Converts LF line endings (Unix) to CR+LF (DOS).

=item conversion =E<gt> sub { CONVERT $_[0] }

When a callback is given, it is invoked repeatly as chunks of data
become available. It has to change C<$_[0]> in place in order to
perform the conversion.

Also, the subroutine is called one last time with and empty data
string to indicate that the transfer has finished, so that
intermediate buffers can be flushed.

Note that when writing conversion subroutines, special care has to be
taken to handle sequences crossing chunk borders.

=back

The data conversion is always performed before any other callback
subroutine is called.

See the Wikipedia entry on line endings
L<http://en.wikipedia.org/wiki/Newline> or the article Understanding
Newlines by Xavier Noria
(L<http://www.onlamp.com/pub/a/onlamp/2006/08/17/understanding-newlines.html>)
for details about the different conventions.

=head1 FAQ

=over 4

=item Closing the connection:

B<Q>: How do I close the connection to the remote server?

B<A>: let the C<$sftp> object go out of scope or just undefine it:

  undef $sftp;

=item Using Net::SFTP::Foreign from a cron script:

B<Q>: I wrote a script for performing sftp file transfers that works
beautifully from the command line. However when I try to run the same
script from cron it fails with a broken pipe error:

  open2: exec of ssh -l user some.location.com -s sftp
    failed at Net/SFTP/Foreign.pm line 67

B<A>: C<ssh> is not on your cron PATH.

The remedy is either to add the location of the C<ssh> application to
your cron PATH or to use the C<ssh_cmd> option of the C<new> method to
hardcode the location of C<ssh> inside your script, for instance:

  my $ssh = Net::SFTP::Foreign->new($host,
                                    ssh_cmd => '/usr/local/ssh/bin/ssh');

=item C<more> constructor option expects an array reference:

B<Q>: I'm trying to pass in the private key file using the -i option,
but it keep saying it couldn't find the key. What I'm doing wrong?

B<A>: The C<more> argument on the constructor expects a single option
or a reference to an array of options. It will not split an string
containing several options.

Arguments to SSH options have to be also passed as different entries
on the array:

  my $sftp = Net::SFTP::Foreign->new($host,
                                      more => [qw(-i /home/foo/.ssh/id_dsa)]);

Note also that latest versions of Net::SFTP::Foreign support the
C<key_path> argument:

  my $sftp = Net::SFTP::Foreign->new($host,
                                      key_path => '/home/foo/.ssh/id_dsa');

=item Plink and password authentication

B<Q>: Why password authentication is not supported for the plink SSH
client?

B<A>: A bug in plink breaks it.

Newer versions of Net::SFTP::Foreign pass the password to C<plink>
using its C<-pw> option. As this feature is not completely secure a
warning is generated.

It can be silenced (though, don't do it without understanding why it
is there, please!) as follows:

  no warnings 'Net::SFTP::Foreign';
  my $sftp = Net::SFTP::Foreign->new('foo@bar',
                                     ssh_cmd => 'plink',
                                     password => $password);
  $sftp->die_on_error;

=item Plink

B<Q>: What is C<plink>?

B<A>: Plink is a command line tool distributed with the
L<PuTTY|http://the.earth.li/~sgtatham/putty/> SSH client. Very popular
between MS Windows users, it is also available for Linux and other
Unixes now.

=item Put method fails

B<Q>: put fails with the following error:

  Couldn't setstat remote file: The requested operation cannot be
  performed because there is a file transfer in progress.

B<A>: Try passing the C<late_set_perm> option to the put method:

  $sftp->put($local, $remote, late_set_perm => 1)
     or die "unable to transfer file: " . $sftp->error;

Some servers do not support the C<fsetstat> operation on open file
handles. Setting this flag allows one to delay that operation until
the file has been completely transferred and the remote file handle
closed.

Also, send me a bug report containing a dump of your $sftp object so I
can add code for your particular server software to activate the
work-around automatically.

=item Put method fails even with late_set_perm set

B<Q>: I added C<late_set_perm =E<gt> 1> to the put call, but we are still
receiving the error "Couldn't setstat remote file (setstat)".

B<A>: Some servers forbid the SFTP C<setstat> operation used by the
C<put> method for replicating the file permissions and timestamps on
the remote side.

As a work around you can just disable the feature:

  $sftp->put($local_file, $remote_file,
             copy_perms => 0, copy_time => 0);

=item Disable password authentication completely

B<Q>: When we try to open a session and the key either doesn't exist
or is invalid, the child SSH hangs waiting for a password to be
entered.  Is there a way to make this fail back to the Perl program to
be handled?

B<A>: Disable anything but public key SSH authentication calling the
new method as follows:

  $sftp = Net::SFTP::Foreign->new($host,
                more => [qw(-o PreferredAuthentications=publickey)])

See L<ssh_config(5)> for the details.

=item Understanding C<$attr-E<gt>perm> bits

B<Q>: How can I know if a directory entry is a (directory|link|file|...)?

B<A>: Use the C<S_IS*> functions from L<Fcntl>. For instance:

  use Fcntl qw(S_ISDIR);
  my $ls = $sftp->ls or die $sftp->error;
  for my $entry (@$ls) {
    if (S_ISDIR($entry->{a}->perm)) {
      print "$entry->{filename} is a directory\n";
    }
  }

=item Host key checking

B<Q>: Connecting to a remote server with password authentication fails
with the following error:

  The authenticity of the target host can not be established,
  connect from the command line first

B<A>: That probably means that the public key from the remote server
is not stored in the C<~/.ssh/known_hosts> file. Run an SSH Connection
from the command line as the same user as the script and answer C<yes>
when asked to confirm the key supplied.

Example:

  $ ssh pluto /bin/true
  The authenticity of host 'pluto (172.25.1.4)' can't be established.
  RSA key fingerprint is 41:b1:a7:86:d2:a9:7b:b0:7f:a1:00:b7:26:51:76:52.
  Are you sure you want to continue connecting (yes/no)? yes

Your SSH client may also support some flag to disable this check, but
doing it can ruin the security of the SSH protocol so I advise against
its usage.

Example:

  # Warning: don't do that unless you fully understand
  # its security implications!!!
  $sftp = Net::SFTP::Foreign->new($host,
                                  more => [-o => 'StrictHostKeyChecking no'],
                                  ...);

=back

=head1 BUGS

These are the currently known bugs:

=over 4

=item - Doesn't work on VMS:

The problem is related to L<IPC::Open3> not working on VMS. Patches
are welcome!

=item - Dirty cleanup:

On some operating systems, closing the pipes used to comunicate with
the slave SSH process does not terminate it and a work around has to
be applied. If you find that your scripts hung when the $sftp object
gets out of scope, try setting C<$Net::SFTP::Foreign::dirty_cleanup>
to a true value and also send me a report including the value of
C<$^O> on your machine and the OpenSSH version.

From version 0.90_18 upwards, a dirty cleanup is performed anyway when
the SSH process does not terminate by itself in 8 seconds or less.

=item - Reversed symlink arguments:

This package uses the non-conforming OpenSSH argument order for the
SSH_FXP_SYMLINK command that seems to be the de facto standard. When
interacting with SFTP servers that follow the SFTP specification, the
C<symlink> method will interpret its arguments in reverse order.

=item - IPC::Open3 bugs on Windows

On Windows the IPC::Open3 module is used to spawn the slave SSH
process. That module has several nasty bugs (related to STDIN, STDOUT
and STDERR being closed or not being assigned to file descriptors 0, 1
and 2 respectively) that will cause the connection to fail.

Specifically this is known to happen under mod_perl/mod_perl2.

=back

Also, the following features should be considered experimental:

- support for Tectia server

- numbered feature

- autodie mode

- best_effort feature

=head1 SUPPORT

To report bugs, send me and email or use the CPAN bug tracking system
at L<http://rt.cpan.org>.

=head2 Commercial support

Commercial support, professional services and custom software
development around this module are available through my current
company. Drop me an email with a rough description of your
requirements and we will get back to you ASAP.

=head2 My wishlist

If you like this module and you're feeling generous, take a look at my
Amazon Wish List: L<http://amzn.com/w/1WU1P6IR5QZ42>

Also consider contributing to the OpenSSH project this module builds
upon: L<http://www.openssh.org/donations.html>.

=head1 SEE ALSO

Information about the constants used on this module is available from
L<Net::SFTP::Foreign::Constants>. Information about attribute objects
is available from L<Net::SFTP::Foreign::Attributes>.

General information about SSH and the OpenSSH implementation is
available from the OpenSSH web site at L<http://www.openssh.org/> and
from the L<sftp(1)> and L<sftp-server(8)> manual pages.

Net::SFTP::Foreign integrates nicely with my other module
L<Net::OpenSSH>.

L<Net::SFTP::Foreign::Backend::Net_SSH2> allows one to run
Net::SFTP::Foreign on top of L<Net::SSH2> (nowadays, this combination
is probably the best option under Windows).

Modules offering similar functionality available from CPAN are
L<Net::SFTP> and L<Net::SSH2>.

L<Test::SFTP> allows one to run tests against a remote SFTP server.

L<autodie>.

=head1 COPYRIGHT

Copyright (c) 2005-2012 Salvador FandiE<ntilde>o (sfandino@yahoo.com).

Copyright (c) 2001 Benjamin Trott, Copyright (c) 2003 David Rolsky.

_glob_to_regex method based on code (c) 2002 Richard Clamp.

All rights reserved.  This program is free software; you can
redistribute it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the LICENSE file included
with this module.

=cut
