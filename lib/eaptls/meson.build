libeap_tls_sources = files('''
    eap.c
    tls_server.c
    eap.h
    tls_server.h
'''.split())

libeap_tls_inc = include_directories('.')
libBearSSL_inc = include_directories('./inc')
libBearSSL = cc.find_library('libbearssl', dirs: meson.current_source_dir())

libeap_tls = library('ogseap-tls',
    sources : libeap_tls_sources,
    version : libogslib_version,
    c_args : '-DOGS_EAP_TLS_COMPILATION',
    include_directories : [libeap_tls_inc, libinc, libBearSSL_inc],
    dependencies: [libcore_dep, libBearSSL],
    install : true)

libeap_tls_dep = declare_dependency(
    link_with : libeap_tls,
    include_directories : [libeap_tls_inc, libinc, libBearSSL_inc],
    dependencies: [libcore_dep, libBearSSL])