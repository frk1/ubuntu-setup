#!/usr/bin/env bash
set -e

printf -- "#########################################\n"
printf -- "# This script has only been tested with #\n"
printf -- "#             Ubuntu 18.04              #\n"
printf -- "#   It might work with other versions   #\n"
printf -- "#########################################\n\n"

###################################################################################
# If you add your public SSH-Key here, password authentication to the server      #
# will be disabled. Using password authentication is NOT recommend!               #
#                                                                                 #
# Remote login as 'root' is disabled by default. If you need to use the root user #
# directly (not recommend), use 'sudo -i' to become root when needed.             #
###################################################################################

export SCRIPT_USERNAME='reactiion'
export SCRIPT_SSH_KEY=''

export VERSION_GIT=2.19.2
export VERSION_TMUX=2.8
export VERSION_VIM=8.1.0549
export VERSION_ZSH=5.6.2
export VERSION_FASD=1.0.1
export VERSION_LIBRESSL=2.8.2
export VERSION_CMAKE=3.13.0
export VERSION_CURL=7.62.0

printf -- "- Adding user '$SCRIPT_USERNAME'...\n\n"
adduser --quiet --gecos "" $SCRIPT_USERNAME

clear;
printf -- "#########################################\n"
printf -- "# This script has only been tested with #\n"
printf -- "#             Ubuntu 18.04              #\n"
printf -- "#   It might work with other versions   #\n"
printf -- "#########################################\n\n"
printf -- "- Adding user '$SCRIPT_USERNAME'...ok\n"

exec 3>&1
exec 4>&2
#exec 1>/dev/null
#exec 2>/dev/null

gpasswd -a $SCRIPT_USERNAME sudo
gpasswd -a $SCRIPT_USERNAME www-data
printf -- "- Updating system..." >&3

cat <<'EOF' > /etc/apt/apt.conf.d/local
Dpkg::Options {
   "--force-confdef";
   "--force-confold";
}
EOF

export DEBIAN_FRONTEND=noninteractive
apt-get -y update
apt-get -y install software-properties-common language-pack-en-base

timedatectl set-timezone Europe/Berlin
export LC_ALL='en_US.UTF-8'
export LANG='en_US.UTF-8'
update-locale LC_ALL="en_GB.UTF-8" LANG="en_GB.UTF-8"

add-apt-repository -y ppa:jonathonf/gcc
add-apt-repository -y ppa:ondrej/php

apt-get -y update
apt-get -y upgrade
apt-get -y dist-upgrade
apt-get -y autoremove
apt-get -y install autoconf                   \
                   automake                   \
                   build-essential            \
                   checkinstall               \
                   clang                      \
                   curl                       \
                   dbus                       \
                   g++                        \
                   g++-7                      \
                   gcc                        \
                   gcc-7                      \
                   gettext                    \
                   git                        \
                   htop                       \
                   iftop                      \
                   jq                         \
                   landscape-common           \
                   libcrypto++-dev            \
                   libcurl4-openssl-dev       \
                   libevent-dev               \
                   libiw-dev                  \
                   libnghttp2-dev             \
                   libprotobuf-dev            \
                   libsqlite3-dev             \
                   libssl-dev                 \
                   libtool                    \
                   libz-dev                   \
                   libgd-dev                  \
                   libgeoip-dev               \
                   m4                         \
                   man                        \
                   mosh                       \
                   musl-tools                 \
                   ncurses-dev                \
                   ncurses-term               \
                   netcat                     \
                   ntp                        \
                   ufw                        \
                   pax                        \
                   pkg-config                 \
                   python                     \
                   python-dev                 \
                   python-pip                 \
                   python3                    \
                   python3-dev                \
                   python3-pip                \
                   software-properties-common \
                   sudo                       \
                   tree                       \
                   vim                        \
                   wget                       \
                   zsh

update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 100 \
                    --slave   /usr/bin/g++ g++ /usr/bin/g++-7

printf -- "ok\n" >&3
printf -- "- Building essentials using toast..." >&3

chmod -R 1777 /tmp
adduser toast --disabled-login --disabled-password --quiet --system
wget -q -O- http://toastball.net/toast/toast-1.488 | perl -x - arm toast

genlink() {
  echo "https://github.com/$1/$2/tarball/$3"
}

toast arm --armdir="/usr/local/libressl"                                              \
          --noreconfigure                                                             \
          --confappend="--disable-shared"                                             \
          --compilecmd="./config -fPIC --disable-shared --prefix=/usr/local/libressl" \
          libressl/$VERSION_LIBRESSL:                                                 \
          "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$VERSION_LIBRESSL.tar.gz"

toast arm --confappend="--with-ssl=/usr/local/libressl --with-nghttp2" \
          curl/$VERSION_CURL:                                          \
          "https://curl.haxx.se/download/curl-$VERSION_CURL.tar.gz"

toast arm --confappend="--without-openssl --with-curl=/usr/local" \
          git/$VERSION_GIT:                                       \
          https://www.kernel.org/pub/software/scm/git/git-$VERSION_GIT.tar.gz

toast arm --confappend="--with-ssl-dir=/usr/local/libressl --with-ldflags=-Wl,-R/usr/local/libressl/lib" \
          ftp://mirror.hs-esslingen.de/pub/OpenBSD/OpenSSH/portable/

toast arm tmux/$VERSION_TMUX:         $(genlink tmux tmux $VERSION_TMUX)                        \
                                      --compilecmd='./autogen.sh && ./configure && make'
toast arm vim/$VERSION_VIM:           $(genlink vim vim v$VERSION_VIM)
toast arm zsh/$VERSION_ZSH:           $(genlink 'zsh-users' zsh "zsh-$VERSION_ZSH")             \
                                      --compilecmd='./Util/preconfig && ./configure && make'    \
                                      --installcmd='make install.bin && make install.modules && make install.fns'
toast arm fasd/$VERSION_FASD:         $(genlink clvv fasd $VERSION_FASD)

wget https://raw.githubusercontent.com/frk1/mirrors/master/rg -O /usr/local/bin/rg
chmod +x /usr/local/bin/rg

wget https://cmake.org/files/v3.13/cmake-$VERSION_CMAKE-Linux-x86_64.tar.gz  -O /tmp/cmake.tar.gz
tar --strip-components 1 -xzvf /tmp/cmake.tar.gz -C /usr/local
curl -sSL http://git.io/git-extras-setup | bash

apt-get -yqq purge nginx nginx-common nginx-full
rm -rf /etc/nginx

printf -- "ok\n" >&3
printf -- "- Configuring user profile..." >&3

printf -- "/usr/local/bin/zsh\n" >> /etc/shells
chsh -s /usr/local/bin/zsh $SCRIPT_USERNAME

if [[ ! -z "$SCRIPT_SSH_KEY" ]]; then
  cd /home/$SCRIPT_USERNAME
  mkdir -p .ssh
  touch .ssh/authorized_keys .ssh/known_hosts
  printf -- "$SCRIPT_SSH_KEY\n" >> .ssh/authorized_keys
  chmod 700 .ssh
  chmod 600 .ssh/authorized_keys
  ssh-keyscan github.com > .ssh/known_hosts
fi

cat <<'EOF' > /home/$SCRIPT_USERNAME/.zshenv
export EDITOR='vim'
export VISUAL='vim'
export PAGER='less'
export LANG='en_US.UTF-8'

export N_PREFIX="$HOME/.n"
export PATH="$N_PREFIX/bin:$HOME/.toast/armed/bin:$HOME/.cargo/bin:$PATH"

typeset -gU cdpath fpath mailpath path
EOF
chown -Rh $SCRIPT_USERNAME /home/$SCRIPT_USERNAME/.zshenv

runuser -l $SCRIPT_USERNAME -c 'zsh -s' <<'EOF'
  cd ~

  git clone --recursive https://github.com/Eriner/zim.git ${ZDOTDIR:-${HOME}}/.zim
  setopt EXTENDED_GLOB
  for template_file ( ${ZDOTDIR:-${HOME}}/.zim/templates/* ); do
    user_file="${ZDOTDIR:-${HOME}}/.${template_file:t}"
    touch ${user_file}
    ( print -rn "$(<${template_file})$(<${user_file})" >! ${user_file} ) 2>/dev/null
  done

  wget -O /tmp/n-install.sh https://git.io/n-install
  wget -O /tmp/rust-install.sh https://sh.rustup.rs
  chmod +x /tmp/{n,rust}-install.sh

  /tmp/n-install.sh -n -y -q latest
  /tmp/rust-install.sh -y --no-modify-path

  rm /tmp/{n,rust}-install.sh

  rehash
  npm i -g npm@latest
  npm i -g coffee-script@latest pm2@latest
  pm2 install coffeescript
  pm2 kill

  rustup target add x86_64-unknown-linux-musl
  rustup toolchain add nightly
  rustup default nightly
  cargo install --force --git https://github.com/ogham/exa.git
EOF

chown -Rh $SCRIPT_USERNAME /home/$SCRIPT_USERNAME

printf -- "ok\n"
printf -- "- Configuring openSSH server..."

cat <<'EOF' > /etc/ssh/sshd_config
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com

AuthenticationMethods publickey
LogLevel INFO
PermitRootLogin No
EOF

cat <<'EOF' > /etc/ssh/ssh_config
HashKnownHosts yes
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-ed25519,ssh-rsa,ecdsa-sha2-nistp521-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
EOF

if [ -z "$SCRIPT_SSH_KEY" ]; then
  sed -i "/AuthenticationMethods/s/publickey/publickey password/g" /etc/ssh/sshd_config
fi

cd /etc/ssh
shred -u ssh_host_*key*
ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ''
ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N ''
systemctl restart sshd

printf -- "ok\n" >&3
printf -- "- Configuring firewall..." >&3

ufw logging on
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

printf -- "ok\n" >&3
printf -- "- Building nginx..." >&3

mkdir -p /tmp/build-nginx
cd /tmp/build-nginx

export NGINX_VERSION=1.15.7
export VERSION_ZLIB=zlib-1.2.11
export VERSION_PCRE=pcre-8.41
export VERSION_LIBRESSL=libressl-$VERSION_LIBRESSL
export VERSION_NGINX=nginx-$NGINX_VERSION

export SOURCE_LIBRESSL=https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/
export SOURCE_PCRE=https://ftp.pcre.org/pub/pcre/
export SOURCE_NGINX=https://nginx.org/download/
export SOURCE_ZLIB=https://zlib.net/

rm -rf build
mkdir build

NB_PROC=$(grep -c ^processor /proc/cpuinfo)

wget -P ./build $SOURCE_PCRE$VERSION_PCRE.tar.gz
wget -P ./build $SOURCE_LIBRESSL$VERSION_LIBRESSL.tar.gz
wget -P ./build $SOURCE_NGINX$VERSION_NGINX.tar.gz
wget -P ./build $SOURCE_ZLIB$VERSION_ZLIB.tar.gz

cd build
tar xzf $VERSION_NGINX.tar.gz
tar xzf $VERSION_LIBRESSL.tar.gz
tar xzf $VERSION_PCRE.tar.gz
tar xzf $VERSION_ZLIB.tar.gz
rm -rf *.tar.gz

cd ./$VERSION_NGINX
./configure --prefix=/usr/share/nginx                                                                                              \
            --sbin-path=/usr/sbin/nginx                                                                                            \
            --modules-path=/usr/lib/nginx/modules                                                                                  \
            --conf-path=/etc/nginx/nginx.conf                                                                                      \
            --error-log-path=/var/log/nginx/error.log                                                                              \
            --http-log-path=/var/log/nginx/access.log                                                                              \
            --pid-path=/run/nginx.pid                                                                                              \
            --lock-path=/var/lock/nginx.lock                                                                                       \
            --user=www-data                                                                                                        \
            --group=www-data                                                                                                       \
            --build=Ubuntu                                                                                                         \
            --http-client-body-temp-path=/var/lib/nginx/body                                                                       \
            --http-fastcgi-temp-path=/var/lib/nginx/fastcgi                                                                        \
            --http-proxy-temp-path=/var/lib/nginx/proxy                                                                            \
            --http-scgi-temp-path=/var/lib/nginx/scgi                                                                              \
            --http-uwsgi-temp-path=/var/lib/nginx/uwsgi                                                                            \
            --with-openssl=../$VERSION_LIBRESSL                                                                                    \
            --with-pcre=../$VERSION_PCRE                                                                                           \
            --with-pcre-jit                                                                                                        \
            --with-zlib=../$VERSION_ZLIB                                                                                           \
            --with-compat                                                                                                          \
            --with-file-aio                                                                                                        \
            --with-threads                                                                                                         \
            --with-http_addition_module                                                                                            \
            --with-http_auth_request_module                                                                                        \
            --with-http_dav_module                                                                                                 \
            --with-http_flv_module                                                                                                 \
            --with-http_gunzip_module                                                                                              \
            --with-http_gzip_static_module                                                                                         \
            --with-http_mp4_module                                                                                                 \
            --with-http_random_index_module                                                                                        \
            --with-http_realip_module                                                                                              \
            --with-http_slice_module                                                                                               \
            --with-http_ssl_module                                                                                                 \
            --with-http_sub_module                                                                                                 \
            --with-http_stub_status_module                                                                                         \
            --with-http_v2_module                                                                                                  \
            --with-http_secure_link_module                                                                                         \
            --with-mail                                                                                                            \
            --with-mail_ssl_module                                                                                                 \
            --with-stream                                                                                                          \
            --with-stream_realip_module                                                                                            \
            --with-stream_ssl_module                                                                                               \
            --with-stream_ssl_preread_module                                                                                       \
            --with-debug                                                                                                           \
            --with-cc-opt='-g -O2 -fPIC -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' \
            --with-ld-opt='-Wl,-Bsymbolic-functions -fPIC -Wl,-z,relro -Wl,-z,now'

make -j $NB_PROC                              \
&& checkinstall --pkgname="nginx-libressl"    \
                --pkgversion="$NGINX_VERSION" \
                --provides="nginx"            \
                --requires="libc6"            \
                --strip=yes                   \
                --stripso=yes                 \
                --backup=yes                  \
                -y                            \
                --install=yes

cat <<EOF > /etc/systemd/system/nginx.service
[Unit]
Description=A high performance web server and a reverse proxy server
After=network.target
[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
TimeoutStopSec=5
KillMode=mixed
[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/nginx.service
rm -f /etc/nginx/*.default

mkdir -p /var/lib/nginx/body
mkdir -p /etc/nginx/conf.d
mkdir -p /var/www
mkdir -p /var/www/default
mkdir -p /var/www/letsencrypt

systemctl daemon-reload
systemctl enable nginx.service
systemctl start nginx.service

printf -- "ok\n" >&3
printf -- "- Configuring nginx..." >&3

curl https://get.acme.sh | sh

mkdir -p /etc/nginx/ssl
rm -f /etc/nginx/conf.d/default.conf

/usr/bin/openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048
/usr/bin/openssl req -new                                               \
            -newkey rsa:4096                                            \
            -days 3650                                                  \
            -nodes                                                      \
            -x509                                                       \
            -subj "/C=NL/ST=Amsterdam/L=Amsterdam/O=Dis/CN=example.org" \
            -keyout /etc/nginx/ssl/nginx-rsa.key                        \
            -out /etc/nginx/ssl/nginx-rsa.crt

/usr/bin/openssl req -new                                               \
            -newkey ec                                                  \
            -pkeyopt ec_paramgen_curve:P-384                            \
            -days 3650                                                  \
            -nodes                                                      \
            -x509                                                       \
            -subj "/C=NL/ST=Amsterdam/L=Amsterdam/O=Dis/CN=example.org" \
            -keyout /etc/nginx/ssl/nginx-ecc.key                        \
            -out /etc/nginx/ssl/nginx-ecc.crt

cat <<'EOF' > /etc/nginx/nginx.conf
user www-data;

worker_processes auto;
worker_rlimit_nofile 100000;
error_log /var/log/nginx/error.log crit;

events {
    worker_connections 4000;
    use epoll;
    multi_accept on;
}

http {
    open_file_cache max=200000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    access_log off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    gzip on;
    gzip_min_length 10240;
    gzip_proxied expired no-cache no-store private auth;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/json application/xml;
    gzip_disable msie6;

    reset_timedout_connection on;
    client_body_timeout 10;
    client_max_body_size 100m;
    send_timeout 2;
    keepalive_timeout 30;
    keepalive_requests 100000;

    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    ssl_dhparam /etc/nginx/ssl/dhparam.pem;
    ssl_ecdh_curve X25519:P-521:P-384:P-256;

    ssl_prefer_server_ciphers on;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';

    resolver 8.8.8.8 8.8.4.4;
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_certificate /etc/nginx/ssl/nginx-ecc.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx-ecc.key;
    ssl_certificate /etc/nginx/ssl/nginx-rsa.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx-rsa.key;

    add_header X-Frame-Options SAMEORIGIN always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy same-origin always;
#   add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload" always;
#   add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://ajax.googleapis.com https://cdnjs.com https://code.jquery.com; style-src 'self' https://fonts.googleapis.com; img-src 'self' blob: https:; font-src 'self' https://themes.googleusercontent.com https://fonts.gstatic.com" always;

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;

        location ^~ /.well-known/acme-challenge/ {
            default_type "text/plain";
            root /var/www/letsencrypt;
        }

        location = /.well-known/acme-challenge/ {
            return 404;
        }

        location / {
            return 301 https://$host$request_uri;
        }
    }

    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name _;

        location / {
            root /var/www/default;
            index index.php index.html index.htm;
            try_files $uri $uri/ =404;
        }
    }

    include mime.types;
    include conf.d/*.conf;
}
EOF

cat <<'EOF' > /etc/nginx/conf.d/example_server.conf.off
server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name csgo.reactiion.net;

  if ($http_user_agent ~* "WordPress") {
    return 444;
  }

  root /var/www/reactiion.net/auth;

  location / {
    index index.php;
    try_files $uri $uri/ =404;
  }

  location ~ \.php$ {
    try_files $uri =404;
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass unix:/run/php/php7.2-fpm.sock;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    include fastcgi_params;
  }
}
EOF

cat <<'EOF' > /etc/nginx/conf.d/example_proxy_server.conf.off
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name "~^auth\d{0,2}\.vitahook\.pw$";

    ssl_certificate /etc/nginx/ssl/test.vitahook.pw-cert.pem;
    ssl_certificate_key /etc/nginx/ssl/test.vitahook.pw-key.pem;

    location / {
        root /var/www/default;
        index index.php index.html index.htm;
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        try_files $uri =404;
        include fastcgi.conf;
        fastcgi_pass unix:/run/php/php7.2-fpm.sock;
    }

    location / {
        proxy_pass http://localhost:8001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF

printf -- "ok\n" >&3
printf -- "- Installing php..." >&3

apt-get -yqq install php7.2          \
                     php7.2-curl     \
                     php7.2-fpm      \
                     php7.2-mysql    \
                     php7.2-dba      \
                     php7.2-mbstring \
                     php7.2-soap     \
                     php7.2-xml      \
                     php7.2-zip

sed -i "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g" /etc/php/7.2/fpm/php.ini
sed -i "s/post_max_size = 8M/post_max_size = 32M/g" /etc/php/7.2/fpm/php.ini
sed -i "s/upload_max_filesize = 2M/upload_max_filesize = 100M/g" /etc/php/7.2/fpm/php.ini

systemctl restart php7.2-fpm

printf -- "ok\n" >&3

rm /etc/apt/apt.conf.d/local

chown -R www-data /var/www
chgrp -R www-data /var/www
chmod -R g+w /var/www
find /var/www -type d -exec chmod 2775 {} \;
find /var/www -type f -exec chmod ug+rw {} \;

printf -- "- Installing pip, pip3, and python tools..." >&3
pip install --upgrade pip setuptools
pip3 install --upgrade pip setuptools
pip3 install --upgrade asciinema httpie glances python-swiftclient python-keystoneclient
printf -- "ok\n" >&3

printf -- "=> Done!\n\n" >&3
