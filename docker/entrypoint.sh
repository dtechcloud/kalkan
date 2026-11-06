#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Entry point of the kalkan image. It runs "kalkan <arguments>" with two preparations:
#   1. A container that runs with --user <uid>:<gid> can get a HOME that it cannot write.
#      The scanners keep their caches below HOME, so HOME moves to a new folder in /tmp.
#   2. When the runs folder is not writable, a warning tells how to fix the volume.
#
# For a shell in the image, use: docker run --rm -it --entrypoint sh <image>

set -eu

if [ ! -w "${HOME:-/nonexistent}" ]; then
    HOME=$(mktemp -d /tmp/kalkan-home.XXXXXX)
    export HOME
fi

runs="${KALKAN_RUNS_DIR:-${KALKAN_HOME:-/opt/kalkan}/runs}"
if [ -d "$runs" ] && [ ! -w "$runs" ]; then
    printf 'kalkan-entrypoint: warning: %s is not writable for uid %s.\n' "$runs" "$(id -u)" >&2
    # The command in the next message is for the user's host shell, so it stays unexpanded.
    # shellcheck disable=SC2016
    printf 'kalkan-entrypoint: warning: mount a writable folder at %s, or run the container with --user "$(id -u):$(id -g)".\n' "$runs" >&2
fi

exec kalkan "$@"
