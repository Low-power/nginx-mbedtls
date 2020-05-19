## nginx-mbedtls

[nginx](http://www.nginx.org) with support for [Mbed TLS](https://tls.mbed.org/).

### Overview

This is a fork of the nginx-polarssl fork that upgrade from PolarSSL 1.2 to Mbed TLS 2.7. Mbed TLS has changed a lot, including its name, when upgrading to this version.

### Building

See [nginx's installation options](http://wiki.nginx.org/InstallOptions) for how to configure/install nginx.

This fork adds:

    --with-mbedtls		Attempt to use the system Mbed TLS installation.
    --with-mbedtls=<path>	Compile nginx statically with the Mbed TLS source code located at <path> (untested).

### License

This work are distrubuted under the [nginx license](http://nginx.org/LICENSE) (Also see https://polarssl.org/foss-license-exception and https://twitter.com/polarssl/status/302083038261678080).

### See Also

Original [nginx-polarssl](https://github.com/Yawning/nginx-polarssl) by Yawning Angel, and a [forked version](https://github.com/alinefr/nginx-polarssl) by Aline Freitas that this fork is based on.
