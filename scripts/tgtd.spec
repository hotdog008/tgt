Name:           scsi-target-utils
Version:        1.0.24
Release:        2%{?dist}
Summary:        The SCSI target daemon and utility programs
Packager:       Roi Dayan <roid@mellanox.com>
Group:          System Environment/Daemons
License:        GPLv2
URL:            http://stgt.sourceforge.net/
Source0:        %{name}-%{version}-%{release}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:  pkgconfig libibverbs-devel librdmacm-devel libxslt libaio-devel
%if %{defined suse_version}
BuildRequires:  docbook-xsl-stylesheets
Requires: aaa_base
%else
Requires(preun): initscripts
%endif
Requires: lsof sg3_utils
ExcludeArch:    s390 s390x

%description
The SCSI target package contains the daemon and tools to setup a SCSI targets.
Currently, software iSCSI targets are supported.


%prep
%setup -q -n %{name}-%{version}-%{release}


%build
%{__make} %{?_smp_mflags} ISCSI_RDMA=1


%install
%{__rm} -rf %{buildroot}
%{__install} -d %{buildroot}%{_sbindir}
%{__install} -d %{buildroot}/etc/bash_completion.d
%{__install} -d %{buildroot}/etc/tgt
%{__install} -d %{buildroot}/usr/lib/systemd/system
%{__install} -d %{buildroot}/usr/lib/tgt/backing-store

%{__install} -p -m 0755 scripts/tgt-setup-lun %{buildroot}%{_sbindir}
%{__install} -p -m 0755 scripts/tgt-admin %{buildroot}/%{_sbindir}/tgt-admin
%{__install} -p -m 0644 scripts/tgt.bashcomp.sh %{buildroot}/etc/bash_completion.d/tgt
%{__install} -p -m 0600 conf/targets.conf %{buildroot}/etc/tgt/targets.conf
%{__install} -p -m 0600 conf/tgtd.conf %{buildroot}/etc/tgt/tgtd.conf
%{__install} -p -m 0644 scripts/tgtd.service %{buildroot}/usr/lib/systemd/system/
%{__install} -p -m 0600 usr/bs_rbd.so %{buildroot}/usr/lib/tgt/backing-store/


pushd usr
%{__make} install DESTDIR=%{buildroot} sbindir=%{_sbindir}

%pre
	rm -rf /etc/tgt/ > /dev/null 2>&1 || :

%post
if [ $1 -eq 1 ] && [ -x /usr/bin/systemctl ] ; then
	# Initial installation
	/usr/bin/systemctl --no-reload preset tgtd.service || :
fi


%preun
if [ $1 -eq 0 ] && [ -x /usr/bin/systemctl ] ; then
	# Package removal, not upgrade
	/usr/bin/systemctl stop tgtd> /dev/null 2>&1 || :
	/usr/bin/systemctl --no-reload disable --now tgtd.service || :
fi


%clean
%{__rm} -rf %{buildroot}


%files
%defattr(-, root, root, -)
%{_sbindir}/tgtd
%{_sbindir}/tgtadm
%{_sbindir}/tgt-setup-lun
%{_sbindir}/tgt-admin
%{_sbindir}/tgtimg
/usr/lib/tgt/backing-store/bs_rbd.so

/etc/tgt/tgtd.conf
/etc/tgt/targets.conf
/etc/bash_completion.d/tgt
/usr/lib/systemd/system/tgtd.service
