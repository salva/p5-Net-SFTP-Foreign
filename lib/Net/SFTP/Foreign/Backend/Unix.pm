package Net::SFTP::Foreign::Backend::Unix;

our $VERSION = '1.63_04';

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SFTP::Foreign);

use Fcntl qw(O_NONBLOCK F_SETFL F_GETFL);
use IPC::Open3;
use IPC::Open2;
use Net::SFTP::Foreign::Helpers qw(_tcroak _ensure_list _debug _hexdump $debug);
use Net::SFTP::Foreign::Constants qw(SSH2_FX_BAD_MESSAGE
				     SFTP_ERR_REMOTE_BAD_MESSAGE);

sub _new { shift }

sub _defaults {
   ( default_queue_size => 32 )
}

sub _init_transport_streams {
    my (undef, $sftp) = @_;
    for my $dir (qw(ssh_in ssh_out)) {
	binmode $sftp->{$dir};
	my $flags = fcntl($sftp->{$dir}, F_GETFL, 0);
	fcntl($sftp->{$dir}, F_SETFL, $flags | O_NONBLOCK);
    }
}

sub _open_dev_null {
    my $sftp = shift;
    my $dev_null;
    unless (open $dev_null, '>', "/dev/null") {
	$sftp->_conn_failed("Unable to redirect stderr to /dev/null");
	return;
    }
    $dev_null
}

sub _ipc_open2_bug_workaround {
    # in some cases, IPC::Open3::open2 returns from the child
    my $pid = shift;
    unless ($pid == $$) {
        require POSIX;
        POSIX::_exit(-1);
    }
}

sub _open3 {
    my $backend = shift;
    my $sftp = shift;
    if (defined $_[2]) {
	my $sftp_err = $_[2];
	my $fno = eval { no warnings; fileno($sftp_err) };
	local *SSHERR;
	unless (defined $fno and $fno >= 0 and
		open(SSHERR, ">>&=", $fno)) {
	    $sftp->_conn_failed("Unable to duplicate stderr redirection file handle: $!");
	    return undef;
	}
	local ($@, $SIG{__DIE__}, $SIG{__WARN__});
	return eval { open3(@_[1,0], ">&SSHERR", @_[3..$#_]) }
    }
    else {
	local ($@, $SIG{__DIE__}, $SIG{__WARN__});
	return eval { open2(@_[0,1], @_[3..$#_]) };
    }
}

sub _init_transport {
    my ($backend, $sftp, $opts) = @_;

    my $transport = delete $opts->{transport};

    if (defined $transport) {
	if (ref $transport eq 'ARRAY') {
            @{$sftp}{qw(ssh_in ssh_out pid)} = @$transport;
        }
        else {
            $sftp->{ssh_in} = $sftp->{ssh_out} = $transport;
            $sftp->{_ssh_out_is_not_dupped} = 1;
        }
    }
    else {
        my $pass = delete $opts->{passphrase};
	my $passphrase;
        if (defined $pass) {
            $passphrase = 1;
        }
        else {
            $pass = delete $opts->{password};
	    defined $pass and $sftp->{_password_authentication} = 1;
        }

        my $expect_log_user = delete $opts->{expect_log_user} || 0;
	my $stderr_discard = delete $opts->{stderr_discard};
	my $stderr_fh = ($stderr_discard ? undef : delete $opts->{stderr_fh});
        my $open2_cmd = delete $opts->{open2_cmd};
        my $ssh_cmd_interface = delete $opts->{ssh_cmd_interface};

	my @open2_cmd;
        if (defined $open2_cmd) {
            @open2_cmd = _ensure_list($open2_cmd);
        }
        else {
            my $host = delete $opts->{host};
            defined $host or croak "sftp target host not defined";

            my $ssh_cmd = delete $opts->{ssh_cmd};
            $ssh_cmd = 'ssh' unless defined $ssh_cmd;
            @open2_cmd = ($ssh_cmd);

            unless (defined $ssh_cmd_interface) {
                $ssh_cmd_interface = ( $ssh_cmd =~ /\bplink(?:\.exe)?$/i ? 'plink'  :
                                       $ssh_cmd =~ /\bsshg3$/i           ? 'tectia' :
                                                                           'ssh'    );
            }

            my $port = delete $opts->{port};
            my $user = delete $opts->{user};
	    my $ssh1 = delete $opts->{ssh1};

            my $more = delete $opts->{more};
            carp "'more' argument looks like if it should be splited first"
                if (defined $more and !ref($more) and $more =~ /^-\w\s+\S/);

            if ($ssh_cmd_interface eq 'plink') {
                $pass and !$passphrase
                    and croak "Password authentication via Expect is not supported for the plink client";
                push @open2_cmd, -P => $port if defined $port;
            }
            elsif ($ssh_cmd_interface eq 'ssh') {
                push @open2_cmd, -p => $port if defined $port;
		if ($pass and !$passphrase) {
		    push @open2_cmd, (-o => 'NumberOfPasswordPrompts=1',
				      -o => 'PreferredAuthentications=keyboard-interactive,password');
		}
            }
            elsif ($ssh_cmd_interface eq 'tectia') {
            }
            else {
                die "Unsupported ssh_cmd_interface '$ssh_cmd_interface'";
            }
            push @open2_cmd, -l => $user if defined $user;
            push @open2_cmd, _ensure_list($more) if defined $more;
            push @open2_cmd, $host;
	    push @open2_cmd, ($ssh1 ? "/usr/lib/sftp-server" : -s => 'sftp');
        }

        my $redirect_stderr_to_tty = ( (defined $pass or defined $passphrase) and
                                       (delete $opts->{redirect_stderr_to_tty} or
                                        $ssh_cmd_interface eq 'tectia' ) );

        $redirect_stderr_to_tty and ($stderr_discard or $stderr_fh)
            and croak "stderr_discard or stderr_fh can not be used together with password/passphrase "
                          . "authentication when Tectia client is used";

	_debug "ssh cmd: @open2_cmd\n" if ($debug and $debug & 1);

	%$opts and return; # Net::SFTP::Foreign will find the
                           # unhandled options and croak

	if (${^TAINT} and Scalar::Util::tainted($ENV{PATH})) {
            _tcroak('Insecure $ENV{PATH}')
        }

	if ($stderr_discard) {
	    $stderr_fh = $backend->_open_dev_null($sftp) or return;
	}

        my $this_pid = $$;

        if (defined $pass) {

            # user has requested to use a password or a passphrase for
            # authentication we use Expect to handle that

            eval { require IO::Pty };
            $@ and croak "password authentication is not available, IO::Pty and Expect are not installed";
            eval { require Expect };
            $@ and croak "password authentication is not available, Expect is not installed";

            local ($ENV{SSH_ASKPASS}, $ENV{SSH_AUTH_SOCK}) if $passphrase;

            my $name = $passphrase ? 'Passphrase' : 'Password';
            my $eto = $sftp->{_timeout} ? $sftp->{_timeout} * 4 : 120;

	    my $child;
	    my $expect;
	    if (eval $IPC::Open3::VERSION >= 1.0105) {
		# open2(..., '-') only works from this IPC::Open3 version upwards;
		my $pty = IO::Pty->new;
		$expect = Expect->init($pty);
		$expect->raw_pty(1);
		$expect->log_user($expect_log_user);

                $redirect_stderr_to_tty and $stderr_fh = $pty;

		$child = $backend->_open3($sftp, $sftp->{ssh_in}, $sftp->{ssh_out}, $stderr_fh, '-');

		if (defined $child and !$child) {
		    $pty->make_slave_controlling_terminal;
		    do { exec @open2_cmd }; # work around suppress warning under mod_perl
		    exit -1;
		}
		_ipc_open2_bug_workaround $this_pid;
		# $pty->close_slave();
	    }
	    else {
                $redirect_stderr_to_tty and
                    croak "In order to support password/passphrase authentication with the Tectia client, " .
                        "IPC::Open3 version 1.0105 is required (current version is $IPC::Open3::VERSION)";
		$expect = Expect->new;
		$expect->raw_pty(1);
		$expect->log_user($expect_log_user);
		$expect->spawn(@open2_cmd);
		$sftp->{ssh_in} = $sftp->{ssh_out} = $expect;
		$sftp->{_ssh_out_is_not_dupped} = 1;
		$child = $expect->pid;
	    }
            unless (defined $child) {
                $sftp->_conn_failed("Bad ssh command", $!);
                return;
            }
            $sftp->{pid} = $child;
            $sftp->{_expect} = $expect;

            unless($expect->expect($eto, ':', '?')) {
                $sftp->_conn_failed("$name not requested as expected", $expect->error);
                return;
            }
	    my $before = $expect->before;
	    if ($before =~ /^The authenticity of host /i or
		$before =~ /^Warning: the \w+ host key for /i) {
		$sftp->_conn_failed("the authenticity of the target host can not be established, connect from the command line first");
		return;
	    }
            $expect->send("$pass\n");
	    $sftp->{_password_sent} = 1;

            unless ($expect->expect($eto, "\n")) {
                $sftp->_conn_failed("$name interchange did not complete", $expect->error);
                return;
            }
	    $expect->close_slave();
        }
        else {
	    $sftp->{pid} = $backend->_open3($sftp, $sftp->{ssh_in}, $sftp->{ssh_out}, $stderr_fh, @open2_cmd);
            _ipc_open2_bug_workaround $this_pid;

            unless (defined $sftp->{pid}) {
                $sftp->_conn_failed("Bad ssh command", $!);
                return;
            }
        }
    }
    $backend->_init_transport_streams($sftp);
}


sub _do_io {
    my (undef, $sftp, $timeout) = @_;

    $debug and $debug & 32 and _debug(sprintf "_do_io connected: %s", $sftp->{_connected} || 0);

    return undef unless $sftp->{_connected};

    my $fnoout = fileno $sftp->{ssh_out};
    my $fnoin = fileno $sftp->{ssh_in};
    my ($rv, $wv) = ('', '');
    vec($rv, $fnoin, 1) = 1;
    vec($wv, $fnoout, 1) = 1;

    my $bin = \$sftp->{_bin};
    my $bout = \$sftp->{_bout};

    local $SIG{PIPE} = 'IGNORE';

    my $len;
    while (1) {
        my $lbin = length $$bin;
	if (defined $len) {
            return 1 if $lbin >= $len;
	}
	elsif ($lbin >= 4) {
            $len = 4 + unpack N => $$bin;
            if ($len > 256 * 1024) {
                $sftp->_set_status(SSH2_FX_BAD_MESSAGE);
                $sftp->_set_error(SFTP_ERR_REMOTE_BAD_MESSAGE,
                                  "bad remote message received");
                return undef;
            }
            return 1 if $lbin >= $len;
        }

        my $rv1 = $rv;
        my $wv1 = length($$bout) ? $wv : '';

        $debug and $debug & 32 and _debug("_do_io select(-,-,-, ". (defined $timeout ? $timeout : 'undef') .")");

        my $n = select($rv1, $wv1, undef, $timeout);
        if ($n > 0) {
            if (vec($wv1, $fnoout, 1)) {
                my $written = syswrite($sftp->{ssh_out}, $$bout, 64 * 1024);
                if ($debug and $debug & 32) {
		    _debug (sprintf "_do_io write queue: %d, syswrite: %s, max: %d, \$!: %s",
			    length $$bout,
			    (defined $written ? $written : 'undef'),
			    64 * 1024, $!);
		    $debug & 2048 and $written and _hexdump(substr($$bout, 0, $written));
		}
                if ($written) {
                    substr($$bout, 0, $written, '');
                }
                elsif ($! != Errno::EAGAIN() and $! != Errno::EINTR()) {
                    $sftp->_conn_lost;
                    return undef;
                }
            }
            if (vec($rv1, $fnoin, 1)) {
                my $read = sysread($sftp->{ssh_in}, $$bin, 64 * 1024, length($$bin));
                if ($debug and $debug & 32) {
		    _debug (sprintf "_do_io read sysread: %s, total read: %d, \$!: %s",
			    (defined $read ? $read : 'undef'),
			    length $$bin,
			    $!);
		    $debug & 1024 and $read and _hexdump(substr($$bin, -$read));
		}
                if (!$read and $! != Errno::EAGAIN() and $! != Errno::EINTR()) {
                    $sftp->_conn_lost;
                    return undef;
                }
            }
        }
        else {
            $debug and $debug & 32 and _debug "_do_io select failed: $!";
            next if ($n < 0 and ($! == Errno::EINTR() or $! == Errno::EAGAIN()));
            return undef;
        }
    }
}

1;
