The full documentation for this example is [available on our documentation site](https://cloud.mbed.com/docs/current/connecting/device-management-client-tutorials.html)

## LPC55S69

Replace `mbed_cloud_dev_credentials.c` with your own credentials.

```
mbed deploy
mbed compile -t GCC_ARM -m LPC55S69_NS --profile release --app-config sdio-glue/configs/mbed-cloud-client-example.json
```

On MacOSX:
```
dd if=BUILD/LPC55S69_NS/GCC_ARM-RELEASE/mbed-cloud-client-example.hex of=/Volumes/LPC55S69/mbed.hex conv=notrunc && sync
```
