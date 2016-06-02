# x509 Reputation - beta version 
##About:
x509rep is an ips_option extension to Snort++ (tested on snort-3.0.0-a3 version).  It allows users to verify the lowest level certificates sent using the SSL protocol in four different ways:
-	by comparing certificate fingerprint with a fingerprint white-list.
-	by comparing certificate fingerprint with fingerprint black-list.
-	by verifying the certificate using trusted certificates saved in a particular folder. 
-	by verifying the certificate using untrusted certificates saved in a particular folder. 

##Available options:
-	black_list_path [< black-list path >]: Path to the black-list fingerprints file. \n 
-	white_list_path [< white-list path >]: Path to the white-list fingerprints file
-	trusted_CA_path [< trusted CA path >]: Path to the trusted CA directory
-	untrusted_CA_path [< untrusted CA path >]: Path to the untrusted CA directory
-	white_fingerprint [< white fingerprint >]: Add a single fingerprint to white-list. Can be used multiple times. 
-	black_fingerprint [< black fingerprint >]: Add a single fingerprint to black-list. Can be used multiple times. 
-	black_list_disable : Disable checking black-list
-	white_list_disable : Disable checking white-list
-	trusted_CA_disable : Disable verifying the certificate with certificates from the trusted CA directory. 
-	untrusted_CA_disable : Disable verifying certificate with certificates from the untrusted CA directory. 
-	logfile [< logfile >]:- Save information about alarm type, time, subject DN, issuer DN to file. 
-	save_cert [< logdir >]: Save suspicious certificates to folder.

*Current depth for the certificate chain verification is 1. 

##Example rules:

All example rules are available in x509rep.rules file.

##Fingerprint format

X509rep uses Secure Hash Algorithm 1 (SHA1).  Fingerprint lists should contain one fingerprint per line in the following format:
XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX:XX
where X represents an upper-case letter or single digit. You can find an example white-list in snort_conf/example_lists directory.

Single fingerprint in snort rule can use upper-case and lower-case letters without colon in between. 

##Trusted and Untrusted CA directory.
The directories should contain certificates in the pem format. Each pem file should contain only one certificate. The certificate filename should be the issuer hash with a “0” file extension. 

```Example : 197722bb.0  where  197722bb is issuer hash```

To get the issuer hash you can use the openssl command:  
```openssl x509 -in <cer> -issuer_hash -noout```

##Installation ( Tested on Ubuntu 14.04 )

To install the required libraries run install-prereqs.sh script as root.

There are two ways to install x509rep plug-in: 
1. you can run the ./build-and-install.sh script as root 
2. you can run the following commands in x509rep folder:
```
snort_path="your/snort/path"
export PKG_CONFIG_PATH="$snort_path/lib/pkgconfig" 
autoreconf -vfi 
./configure --prefix="$snort_path" --with-snort-includes="$snort_path/include/snort" 
make
make install
```
