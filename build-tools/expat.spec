%global unversion 2_7_2

Summary: An XML parser library
Name: expat
Version: %(echo %{unversion} | sed 's/_/./g')
Release: 1%{?dist}
Source0: https://github.com/libexpat/libexpat/releases/download/R_%{unversion}/expat-%{version}.tar.gz

URL: https://libexpat.github.io/
License: MIT
BuildRequires: autoconf, libtool, gcc-c++
BuildRequires: make

%description
This is expat, the C library for parsing XML, written by James Clark. Expat
is a stream oriented XML parser. This means that you register handlers with
the parser prior to starting the parse. These handlers are called when the
parser discovers the associated structures in the document being parsed. A
start tag is an example of the kind of structures for which you may
register handlers.

%package devel
Summary: Libraries and header files to develop applications using expat
Requires: expat%{?_isa} = %{version}-%{release}

%description devel
The expat-devel package contains the libraries, include files and documentation
to develop XML applications with expat.

%package static
Summary: expat XML parser static library
Requires: expat-devel%{?_isa} = %{version}-%{release}

%description static
The expat-static package contains the static version of the expat library.
Install it if you need to link statically with expat.

%prep
%autosetup
sed -i 's/install-data-hook/do-nothing-please/' lib/Makefile.am
./buildconf.sh

%build
export CFLAGS="$RPM_OPT_FLAGS -fPIC"
export DOCBOOK_TO_MAN="xmlto man --skip-validation"
%configure
%make_build

%install
%make_install

rm -f $RPM_BUILD_ROOT%{_libdir}/*.la

%check
make check

%ldconfig_scriptlets

%files
%doc AUTHORS Changes
%license COPYING
%{_bindir}/*
%{_libdir}/libexpat.so.1
%{_libdir}/libexpat.so.1.*
%{_mandir}/*/*

%files devel
%doc doc/reference.html doc/*.css examples/*.c
%{_libdir}/libexpat.so
%{_libdir}/pkgconfig/*.pc
%{_includedir}/*.h
%{_libdir}/cmake/expat-%{version}

%files static
%{_libdir}/libexpat.a

%changelog
* Mon Oct 06 2025 Your Name <your.email@domain.com> - 2.7.2-1
- Initial build for UBI9/RHEL9/CentOS9