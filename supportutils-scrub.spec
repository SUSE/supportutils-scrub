#
# spec file for package supportutils-scrub
#
# Copyright (c) 2024 SUSE Software Solutions Germany GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/

Name:           supportutils-scrub
Version:        1.0
Release:        0
Summary:        Utility to sanitize and remove sensitive data from supportconfig tarballs
License:        GPL-2.0
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildArch:      noarch
Requires:       python3

%description
Supportutils-scrub is a utility designed to sanitize and remove sensitive or unwanted data from
SUSE supportconfig tarballs. It assists users and organizations in aligning with data protection
policies, privacy requirements, and GDPR compliance standards.

%prep
%setup -q

%build

%install
pwd; ls -la
rm -rf $RPM_BUILD_ROOT

# Create necessary directories
install -d $RPM_BUILD_ROOT/usr/lib/supportutils-scrub/supportutils_scrub
install -d $RPM_BUILD_ROOT/usr/lib/supportutils-scrub
install -d $RPM_BUILD_ROOT/etc/supportutils-scrub
install -d $RPM_BUILD_ROOT/sbin
install -d $RPM_BUILD_ROOT/usr/share/man/man8
install -d $RPM_BUILD_ROOT/usr/share/man/man5


# Install the executable script
install -m 0755 bin/supportutils-scrub $RPM_BUILD_ROOT/sbin/supportutils-scrub

# Install the configuration file
install -m 0644 config/supportutils-scrub.conf $RPM_BUILD_ROOT/etc/supportutils-scrub/supportutils-scrub.conf

# Install the manpages
install -m 0644 man/supportutils-scrub.8  $RPM_BUILD_ROOT/usr/share/man/man8/supportutils-scrub.8
gzip  $RPM_BUILD_ROOT/usr/share/man/man8/supportutils-scrub.8
install -m 0644 man/supportutils-scrub.conf.5  $RPM_BUILD_ROOT/usr/share/man/man5/supportutils-scrub.conf.5
gzip  $RPM_BUILD_ROOT/usr/share/man/man5/supportutils-scrub.conf.5

# Install the Python modules
cp -r src/supportutils_scrub/* $RPM_BUILD_ROOT/usr/lib/supportutils-scrub/supportutils_scrub/

%files
%defattr(-,root,root)
/sbin/supportutils-scrub
/etc/supportutils-scrub
/etc/supportutils-scrub/supportutils-scrub.conf
/usr/lib/supportutils-scrub/
/usr/share/man/man8/supportutils-scrub.8.gz
/usr/share/man/man5/supportutils-scrub.conf.5.gz


%clean
rm -rf $RPM_BUILD_ROOT

%postun
# Remove the directories if they are empty
if [ "$1" -eq 0 ]; then
    rm -rf /usr/lib/supportutils-scrub
    rm -rf /etc/supportutils-scrub
    rm -rf /usr/share/man/man8.gz
    rm -rf /usr/share/man/man5.gz
fi
%changelog
* Mon Aug 28 2024 Ronald Pina <ronald.pina@suse.com> - 1.0-0
- Initial package creation

