#!/usr/bin/env bash
set -e

github_get_latest_tag() {
  curl -sSL https://api.github.com/repos/$1/$2/tags                                            \
  | jq 'map(select(.name | test("^(zsh-)?v?[0-9\\.]+$", "ig"))) | map(.name) | sort | reverse | .[0]' \
  | sed 's/[^0-9\.]//g'
}

VERSION_GIT=$(github_get_latest_tag git git)
VERSION_TMUX=$(github_get_latest_tag tmux tmux)
VERSION_VIM=$(github_get_latest_tag vim vim)
VERSION_ZSH=$(github_get_latest_tag zsh-users zsh)
VERSION_FASD=$(github_get_latest_tag clvv fasd)
VERSION_LIBRESSL=$(github_get_latest_tag libressl-portable portable)
VERSION_CMAKE=$(github_get_latest_tag Kitware CMake)

sed -i -r -e "s/VERSION_GIT=[0-9\\.]+/VERSION_GIT=$VERSION_GIT/g"                \
          -e "s/VERSION_TMUX=[0-9\\.]+/VERSION_TMUX=$VERSION_TMUX/g"             \
          -e "s/VERSION_VIM=[0-9\\.]+/VERSION_VIM=$VERSION_VIM/g"                \
          -e "s/VERSION_ZSH=[0-9\\.]+/VERSION_ZSH=$VERSION_ZSH/g"                \
          -e "s/VERSION_FASD=[0-9\\.]+/VERSION_FASD=$VERSION_FASD/g"             \
          -e "s/VERSION_LIBRESSL=[0-9\\.]+/VERSION_LIBRESSL=$VERSION_LIBRESSL/g" \
          -e "s/VERSION_CMAKE=[0-9\\.]+/VERSION_CMAKE=$VERSION_CMAKE/g"          \
              ubuntu-setup.sh
