%define name python-cb-infoblox-connector
%define version 1.3
%define unmangled_version 1.3
%define release 2
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black InfoBlox Connector
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Bit9
Url: http://www.bit9.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller cb-infoblox-connector.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%pre
if [ -f "/etc/cb/integrations/infoblox/infoblox.conf" ]; then
    cp /etc/cb/integrations/infoblox/infoblox.conf /tmp/__bridge.conf.backup
fi

%post
if [ -f "/tmp/__bridge.conf.backup" ]; then
    mv /tmp/__bridge.conf.backup /etc/cb/integrations/infoblox/infoblox.conf
fi

%posttrans
chkconfig --add cb-infoblox-connector
chkconfig --level 345 cb-infoblox-connector on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-infoblox-connector start

%preun
/etc/init.d/cb-infoblox-connector stop

# only delete the chkconfig entry when we uninstall for the last time,
# not on upgrades
if [ "X$1" = "X0" ]
then
    echo "deleting InfoBlox chkconfig entry on uninstall"
    chkconfig --del cb-infoblox-connector
fi


%files -f INSTALLED_FILES
%defattr(-,root,root)

