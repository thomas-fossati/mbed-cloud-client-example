## An attestation demo on LPC55S69 boards

```
git clone -b LPC55S69 https://github.com/thomas-fossati/mbed-cloud-client-example.git
cd mbed-cloud-client-example
```

Replace `mbed_cloud_dev_credentials.c` with your own credentials.

```
mbed deploy
```

Change `nsapi.default-wifi-ssid` and `nsapi.default-wifi-password` in `mbed_app.json` to match your local WiFi settings.

```
mbed compile -t GCC_ARM -m LPC55S69_NS --profile release
```

On Unices:
```
dd if=BUILD/LPC55S69_NS/GCC_ARM-RELEASE/mbed-cloud-client-example.hex of=/Volumes/LPC55S69/mbed.hex conv=notrunc && sync
```

To extract the embedded IAT:
```
cat <base64 encoded attested reading> | \
	base64 -d | \
	cbor2diag.rb | \
	egrep -o "h'[0-9A-F]+'" | \
	cut -c3- | \
	tr -d "'" | \
	xxd -r -p > iat.cbor
```

To verify it you need the IAK public key:
```
cat iak-pub.pem
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd3Jlb4FLOZJ51eHxeB+sbwmaPFyh
sONTUYNLCLZeC1clkM2vj3aTYbzzSs/BHl4HToQmvd4Evm5lOUVElhfeRQ==
-----END PUBLIC KEY-----
```

and use the IAT verifier as follows:
```
check_iat -k iak-pub.pem -p iat.cbor

```
