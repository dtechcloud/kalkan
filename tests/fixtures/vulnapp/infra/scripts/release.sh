#!/bin/bash
# Release helper of the vulnapp shop.

STAGE_DIR=$VULNAPP_STAGE

run_hook() {
  eval "$1"
}

run_hook_checked() {
  case "$1" in
    restart) systemctl restart vulnapp ;;
    reload) systemctl reload vulnapp ;;
    *) echo "unknown hook: $1" >&2; return 1 ;;
  esac
}

clean_stage() {
  rm -rf $STAGE_DIR/
}

clean_stage_checked() {
  rm -rf -- "${STAGE_DIR:?}/"
}

push_build() {
  ssh deploy@web.vulnapp.internal "tar -xzf $1 -C /srv/vulnapp"
}

push_build_checked() {
  scp -- "$1" deploy@web.vulnapp.internal:/srv/incoming/release.tgz
  ssh deploy@web.vulnapp.internal 'tar -xzf /srv/incoming/release.tgz -C /srv/vulnapp'
}
