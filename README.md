## How to use

```sh
apt-get update -yqq                                                                  \
&& apt-get install -yqq sed wget                                                     \
&& wget --no-check-certificate                                                       \
https://raw.githubusercontent.com/frk1/ubuntu-setup/master/ubuntu-setup.sh           \
&& sed -ie s/SCRIPT_USERNAME='frk'/SCRIPT_USERNAME='YOUR_USERNAME'/g ubuntu-setup.sh \
&& chmod +x ubuntu-setup.sh                                                          \
&& ./ubuntu-setup.sh
```

**REMEMBER TO CHANGE `YOUR_USERNAME` !!!**

