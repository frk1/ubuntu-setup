## How to use

##### Ubuntu 18.04
```sh
apt-get update -yq                                                                       \
&& apt-get install -yq wget nano vim                                                     \
&& wget --no-check-certificate                                                           \
https://raw.githubusercontent.com/ReactiioN1337/ubuntu-setup/master/ubuntu-setup-1804.sh \
&& chmod +x ubuntu-setup-1804.sh
```

##### Ubuntu 16.04
```sh
apt-get update -yq                                                                       \
&& apt-get install -yq wget nano vim                                                     \
&& wget --no-check-certificate                                                           \
https://raw.githubusercontent.com/ReactiioN1337/ubuntu-setup/master/ubuntu-setup-1604.sh \
&& chmod +x ubuntu-setup-1604.sh
```

Now open `ubuntu-setup-1604.sh` or `ubuntu-setup-1804.sh` using `nano` or `vim` and change
* `SCRIPT_USERNAME` to your preferred username
* `SCRIPT_SSH_KEY` to your public ssh key

I highly recommend using a ssh key for security! If you do not add your SSH key, password authentication will stay enabled.

Then execute the script and wait - Depending on your server it may take up to 30min to finish the script.

##### Ubuntu 18.04
```sh
./ubuntu-setup-1804.sh
```

##### Ubuntu 16.04
```sh
./ubuntu-setup-1604.sh
```
