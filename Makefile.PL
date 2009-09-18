
require 5.006;

use ExtUtils::MakeMaker;

WriteMakefile( NAME => 'Net::SFTP::Foreign',
	       VERSION_FROM => 'lib/Net/SFTP/Foreign.pm',
	       AUTHOR => 'Salvador Fandino <sfandino@yahoo.com>',
	       ABSTRACT => 'Secure File Transfer Protocol client',
	       PREREQ_PM => { Test::More => 0,
                              Scalar::Util => 0 } );
