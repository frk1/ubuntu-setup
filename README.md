## How to use

```sh
apt-get update -yq                                                         \
&& apt-get install -yq wget nano vim                                       \
&& wget --no-check-certificate                                             \
https://raw.githubusercontent.com/frk1/ubuntu-setup/master/ubuntu-setup.sh \
&& chmod +x ubuntu-setup.sh
```

Now open `ubuntu-setup.sh` using `nano` or `vim` and change
* `SCRIPT_USERNAME` to your preferred username
* `SCRIPT_SSH_KEY` to your public ssh key

I highly recommend using a ssh key for security! If you do not add your SSH key, password authentication will stay enabled.

Then execute the script and wait - Depending on your server it may take up to 30min to finish the script.

```sh
./ubuntu-setup.sh
```

