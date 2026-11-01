#!/usr/bin/env bash

# Script used by CI to upload a packaged build to builds.session.codes, from the directory holding
# it.  SSH_KEY holds the upload key.

set -o errexit

if [ -z "$SSH_KEY" ]; then
    echo -e "\n\n\n\e[31;1mUnable to upload artifact: SSH_KEY not set\e[0m"
    exit 1
fi

echo "$SSH_KEY" >ssh_key

set -o xtrace  # Don't start tracing until *after* we write the ssh key

chmod 600 ssh_key

# Tag first: a tag build has a branch too, which Woodpecker sets to the tag's ref (refs/tags/v1.2.3).
branch_or_tag=${CI_COMMIT_TAG:-${CI_COMMIT_BRANCH:-unknown}}

upload_to="builds.session.codes/${CI_REPO// /_}/${branch_or_tag// /_}"

shopt -s nullglob
filename=(libsession-util-*.tar.xz libsession-util-*.zip)
if [ ${#filename[@]} != 1 ]; then
    echo "Expected (exactly) one file to upload, found: ${filename[*]}" >&2
    exit 1
fi

# sftp doesn't have any equivalent to mkdir -p, so we have to split the above up into a chain of
# -mkdir a/, -mkdir a/b/, -mkdir a/b/c/, ... commands.  The leading `-` allows the command to fail
# without error.
upload_dirs=(${upload_to//\// })
mkdirs=
dir_tmp=""
for p in "${upload_dirs[@]}"; do
    dir_tmp="$dir_tmp$p/"
    mkdirs="$mkdirs
-mkdir $dir_tmp"
done

sftp -i ssh_key -b - -o StrictHostKeyChecking=off drone@builds.session.codes <<SFTP
$mkdirs
put $filename $upload_to
SFTP

set +o xtrace

echo -e "\n\n\n\n\e[32;1mUploaded to https://${upload_to}/${filename}\e[0m\n\n\n"

